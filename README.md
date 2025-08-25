# Employee Monitoring System

## Overview
A secure, real-time monitoring system that allows directors to view employee machine screens simultaneously. The system supports up to 200+ concurrent clients with encrypted communication and modern GUI interfaces.

## Security Features
- **End-to-end encryption** using AES-256
- **Authentication system** with secure key exchange
- **Prepared statements** to prevent injection attacks
- **Rate limiting** to prevent abuse
- **Secure key storage** with hardware-backed encryption where available

## Remote Control Features
- **Remote Reboot**: Reboot individual clients or all clients simultaneously
- **Remote Shutdown**: Shutdown individual clients remotely
- **Service Management**: Start, stop, restart monitoring services on clients
- **Command Broadcasting**: Send commands to all connected clients at once
- **Command History**: Track and log all remote commands and responses

## Communication Features
- **Real-time Messaging**: Send instant messages to individual clients
- **Chat Interface**: Facebook-style popup messaging window with white/blizzard blue theme
- **Message History**: Store and track all client-server communications
- **Secure Messaging**: Encrypted message transmission

## File System Access
- **Remote File Browser**: Browse client file systems from the server
- **File Operations**: View, download, copy, move, delete, and create files remotely
- **Directory Navigation**: Navigate through client directory structures
- **File Content Viewer**: Display text files and binary file information
- **Permission Handling**: Secure access with proper error handling

## Components

### Server
- Multi-threaded architecture supporting 200+ concurrent clients
- Real-time screen capture display
- Client management dashboard
- Activity logging and audit trails
- Cross-platform compatibility (Windows, Linux, macOS, Unix)

### Client
- **Command Line Client**: Lightweight background process with minimal resource usage
- **GUI Client**: Modern interface with system tray support, status monitoring, and easy controls
- **System Tray Integration**: Runs in background with easy access from taskbar
- **Message Popup**: Facebook-style message popup for server communications
- **Real-time Status**: Live connection status and monitoring controls
- **Minimize to Tray**: Option to minimize to system tray instead of closing
- Automatic reconnection handling
- Secure communication protocols
- Cross-platform compatibility

## Installation

### Prerequisites
- Python 3.8+
- Cross-platform compatibility

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Server
```bash
python server.py
```

### Run Client

#### Command Line Client
```bash
python client.py
```

#### GUI Client (Recommended)
```bash
# Windows
run_gui_client.bat

# Linux/Mac
./run_gui_client.sh
```

The GUI client provides a modern interface that runs from the system tray and can be minimized.

### Service Installation

#### Windows Service
```bash
# Run as Administrator
python installer/install_windows_service.py
```

#### Linux Service
```bash
# Run as root
sudo ./installer/install_linux_service.sh install
```

## Usage

### Server Setup
1. Run `server.py` to start the monitoring server
2. Configure server settings in `config.ini`
3. Access the web dashboard at `http://localhost:8080`

### Client Setup
1. Run `client.py` on employee machines
2. Enter server IP address and authentication credentials
3. Client will automatically connect and begin monitoring

### Remote Control Usage
1. **Individual Client Control**: Use the control buttons on each client thumbnail
   - 🔄 Reboot: Reboot the specific client
   - ⏹ Shutdown: Shutdown the specific client
   - ⚙ Service: Restart the monitoring service

2. **Broadcast Commands**: Use toolbar buttons to control all clients
   - 🔄 All: Reboot all connected clients
   - ⚙ All: Restart services on all clients

3. **Service Management**: Install clients as system services for automatic startup

### Messaging Usage
1. **Send Messages**: Click the 💬 button on any client thumbnail
2. **Message Popup**: A small popup window appears at the bottom of the screen
3. **Type Message**: Enter your message in the text area
4. **Send**: Click "Send Message" to deliver the message to the client
5. **Message History**: All messages are logged in the database

### File System Access Usage
1. **Open File Browser**: Click the 📁 button on any client thumbnail
2. **Navigate Directories**: Double-click folders to explore, double-click files to view
3. **File Operations**:
   - **View**: Click "View" to see file contents
   - **Download**: Click "Download" to save files locally
   - **Delete**: Click "Delete" to remove files (with confirmation)
4. **Refresh**: Use the 🔄 button to refresh directory listings
5. **Path Display**: Current directory path is shown at the top

## Security Considerations
- All communication is encrypted
- Authentication required for all connections
- Rate limiting prevents abuse
- Audit logs track all activities
- No sensitive data stored locally

## Testing New Features

### Test Messaging and File Operations
```bash
# Test the new messaging and file system functionality
python testing_systems/test_messaging_and_files.py

# Test file access functionality specifically
python testing_systems/test_file_access.py

# Run comprehensive system test
python testing_systems/test_complete_system.py
```

This test script will:
- Connect to the server as a test client
- Send test messages and file operations
- Verify server responses
- Test the complete communication flow

### Manual Testing
1. **Start the server**: `python server.py`
2. **Start a client**: `python client.py`
3. **Test messaging**: Click the 💬 button on a client thumbnail
4. **Test file browser**: Click the 📁 button on a client thumbnail
5. **Verify functionality**: Check that messages are sent and file operations work

## Cross-Platform Support
- **Windows**: Native support with Windows-specific optimizations
- **Linux**: Full compatibility with systemd integration
- **macOS**: Native support with security framework integration
- **Unix**: Generic Unix system support

## License
This project is for authorized monitoring purposes only. Ensure compliance with local privacy laws and company policies.

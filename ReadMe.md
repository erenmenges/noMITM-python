# Description

This project implements a secure and scalable client-server communication system designed to facilitate encrypted message exchanges. The system comprises two main components: the Server (serverMain.py) and the Client (clientMain.py). Both components are designed to ensure data confidentiality, integrity, and authenticity.

Key Features
Secure Communication with TLS:
TLS Integration
Certificate Validation
Configurable TLS Settings

Cryptographic Key Management:
Key Generation and Storage
Session Key Derivation using ECDH
Key Renewal and Failure Handling

Robust Session Management:
Session Establishment
Heartbeat Mechanism
Activity Tracking
Concurrent Client Handling
Thread-Safe Operations

Comprehensive Error Handling and Logging:
Detailed Logging
Resource Management and Cleanup
Secure Memory Clearance

## Purpose

This project implements a robust and secure client-server communication system designed for applications requiring high-security standards and reliable data exchange. The system prioritizes security, scalability, and reliability through several key architectural decisions:

## Security Features

### Cryptographic Operations

- **Encryption**
  - AES-256-GCM for symmetric encryption with authenticated encryption
  - Secure nonce generation and management with replay protection
  - Automatic key rotation based on time and message count thresholds
  - Perfect forward secrecy through session key derivation
  - Memory-safe key handling with secure cleanup

- **Key Management**
  - ECDSA with SECP256R1 curve for asymmetric operations
  - HKDF-based session key derivation with context binding
  - Secure key storage with encryption at rest
  - Automatic key renewal on encryption failures
  - Key material zeroization after use

### Transport Security

- **TLS Integration**
  - TLS 1.2+ enforcement with configurable minimum version
  - Strong cipher suite selection (ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384)
  - Certificate-based authentication with chain validation
  - Hostname verification and certificate pinning support
  - Session ticket control and reuse policies

### Message Security

- **Message Integrity**
  - Sequence number validation for replay protection
  - Cryptographic timestamps for message freshness
  - HMAC-SHA256 for message authentication
  - JSON structure validation against injection attacks
  - Size limits and content validation

- **Session Management**
  - Secure session establishment with key exchange
  - Automatic session recovery and reconnection
  - Configurable session timeouts and renewal
  - Activity monitoring and heartbeat mechanism
  - State verification and consistency checks

### Resource Management

- **Cleanup and Safety**
  - Automatic resource cleanup with timeouts
  - Secure deletion of temporary files
  - Memory wiping for sensitive data
  - Thread-safe operations with proper locking
  - Connection state monitoring and cleanup

## Shortcomings and Known Limitations

### Security Considerations

- **Key Management**
  - Session keys stored in memory during active connections
  - Potential vulnerability to cold boot attacks
  - No hardware security module (HSM) integration
  - Limited key rotation strategies for long-running sessions

- **Certificate Handling**
  - Limited OCSP stapling support
  - No automatic certificate renewal
  - Certificate revocation checking is basic

### Protocol Restrictions

- **Message Format**
  - Fixed message structure with limited flexibility
  - Maximum message size capped at 1MB
  - No streaming support for large messages
  - Limited support for custom message types

- **State Management**
  - Synchronous state verification
  - No distributed state management
  - Limited state persistence options
  - State recovery requires full reconnection

## Usage

### Default Mode (No TLS)

#### Server

```python
from server.serverMain import Server

# Initialize server
server = Server(host="localhost", port=12345)

# Optional: Set custom message handler
def message_handler(client_id: str, message: str):
    print(f"Received from {client_id}: {message}")
server.set_message_handler(message_handler)

# Start server
server.start()
```

#### Client

```python
from client.clientMain import Client

# Initialize client
client = Client()

# Establish secure session
success = client.establish_secure_session(("localhost", 12345))
if success:
    # Start listening for messages
    client.start_listening()
    
    # Send message
    client.send_message("Hello, secure world!")
```

### TLS Mode

#### Server

```python
from server.serverMain import Server
from config.security_config import TLSConfig

# Configure TLS
tls_config = TLSConfig(
    enabled=True,
    cert_path="path/to/server.crt",
    key_path="path/to/server.key",
    ca_path="path/to/ca.crt",
    verify_mode="CERT_REQUIRED"  # Enforce client certificate verification
)

# Initialize and start server
server = Server(
    host="localhost", 
    port=12345,
    tls_config=tls_config
)
server.start()
```

#### Client

```python
from client.clientMain import Client
from config.security_config import TLSConfig

# Configure TLS
tls_config = TLSConfig(
    enabled=True,
    cert_path="path/to/client.crt",
    key_path="path/to/client.key",
    ca_path="path/to/ca.crt"
)

# Initialize client with TLS
client = Client(tls_config=tls_config)

# Establish secure session
success = client.establish_secure_session(("localhost", 12345))
```

### Methods

#### Server Public Methods

start(): Starts the server and begins accepting connections

shutdown(): Gracefully shuts down the server and cleans up resources

get_client_ids() -> list: Returns list of connected client IDs

close_client_connection(client_id: str): Closes connection with specific client

send_message(client_id: str, message: str) -> bool: Sends encrypted message to specific client

#### Client Public Methods

establish_secure_session(destination: Tuple[str, int]) -> bool: Establishes secure connection with server

send_message(message: str) -> bool: Sends encrypted message to server
start_listening(): Starts listening for incoming messages

stop_listening(): Stops listening for messages

shutdown(): Gracefully closes connection and cleans up resources

is_connected() -> bool: Checks if client has active connection

register_error_handler(handler): Registers callback for error notifications

register_state_change_handler(handler): Registers callback for connection state changes.



## Installation

### Prerequisites

- Python 3.8 or higher
- OpenSSL 1.1.1 or higher

### Step-by-Step Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/secure-communication-system.git
   cd secure-communication-system
   ```

2. **Create and Activate Virtual Environment** (Recommended)

   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate

   # On Unix/MacOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Required Dependencies**

   ```bash
   pip3 install -r requirements.txt
   ```

4. **Generate Test Certificates** (Required for TLS-mode)

   ```bash
   python scripts/generate_test_certs.py
   ```

   This will create necessary certificates in the `test_certs` directory:
   - `ca.crt` - Certificate Authority certificate
   - `server.crt` and `server.key` - Server certificate and private key
   - `client.crt` and `client.key` - Client certificate and private key

5. **Configure TLS Settings** (Optional)
   - Copy `config/tls_config.example.json` to `config/tls_config.json`
   - Modify the paths to match your certificate locations

   ```json
   {
     "enabled": true,
     "cert_path": "path/to/cert.crt",
     "key_path": "path/to/key.pem",
     "ca_path": "path/to/ca.crt"
   }
   ```
   
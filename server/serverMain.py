from Communications import packageMessage, parseMessage, sendData, receiveData, MessageType
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event, log_error, ErrorCode
import threading
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import time

class Server:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # Store client connections
        self.running = False
        self.connection_timeout = 30  # 30 seconds timeout
        self.key_manager = KeyManagement()
        self.nonce_manager = NonceManager()

    def start(self):
        """Start the server and listen for connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            while self.running:
                try:
                    # Accept connections with timeout
                    self.server_socket.settimeout(1.0)  # 1 second timeout for accept
                    conn, addr = self.server_socket.accept()
                    
                    # Set timeout for client connections
                    conn.settimeout(self.connection_timeout)
                    
                    # Store client connection
                    client_id = str(addr)
                    self.clients[client_id] = {
                        'connection': conn,
                        'address': addr,
                        'last_activity': time.time()
                    }
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    # Check for inactive clients
                    self.cleanup_inactive_clients()
                    continue
                    
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Server error: {e}")
            self.shutdown()

    def cleanup_inactive_clients(self):
        """Remove inactive client connections."""
        current_time = time.time()
        inactive_clients = []
        
        for client_id, client_data in self.clients.items():
            if current_time - client_data['last_activity'] > self.connection_timeout:
                inactive_clients.append(client_id)
                
        for client_id in inactive_clients:
            self.close_client_connection(client_id)

    def close_client_connection(self, client_id):
        """Safely close a client connection."""
        if client_id in self.clients:
            try:
                conn = self.clients[client_id]['connection']
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Error closing client connection: {e}")
            finally:
                del self.clients[client_id]

    def shutdown(self):
        """Shutdown the server and cleanup all resources."""
        self.running = False
        
        # Close all client connections
        client_ids = list(self.clients.keys())  # Create a copy of keys
        for client_id in client_ids:
            try:
                # Send termination message to clients
                client_data = self.clients[client_id]
                conn = client_data['connection']
                termination_message = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=int(time.time()),
                    type=MessageType.SESSION_TERMINATION
                )
                try:
                    sendData(conn, termination_message)
                except Exception:
                    pass  # Continue cleanup even if sending fails
                
                # Close connection
                self.close_client_connection(client_id)
                
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Error during client cleanup: {e}")

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        # Clear all internal state
        self.clients.clear()
        self.key_manager.clear_session_keys()
        self.nonce_manager.cleanup_old_nonces()
        
        log_event("Server", "Server shutdown complete")

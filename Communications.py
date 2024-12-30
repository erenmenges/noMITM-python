import json
import socket
import time

# Communication Module Functions

# Message Packaging and Parsing

def packageMessage(encryptedMessage, signature, nonce, timestamp):
    # Create a dictionary with the message details
    message_package = {
        "encryptedMessage": encryptedMessage,
        "signature": signature,
        "nonce": nonce,
        "timestamp": timestamp
    }
    # Serialize the dictionary to a JSON string for transmission
    return json.dumps(message_package)

def parseMessage(package):
    """
    Parses a received message package.

    Args:
        package (str): The JSON string containing the message package.

    Returns:
        dict: A dictionary containing the parsed message details.
    """
    # Deserialize the JSON string to a Python dictionary
    return json.loads(package)

# Network Communication

def sendData(destination, data):
    # Create a socket object for TCP communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the destination server
        s.connect(destination)
        # Send the data after encoding it to bytes
        s.sendall(data.encode('utf-8'))

def receiveData():
    # Create a socket object for TCP communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to a specific address and port
        s.bind(("0.0.0.0", 8080))
        # Start listening for incoming connections
        s.listen()
        # Accept a connection from a client
        conn, addr = s.accept()
        with conn:
            print(f"Connection established with {addr}")
            # Receive data from the client
            data = conn.recv(1024)  # Buffer size is 1024 bytes
            return data.decode('utf-8')

# Key Renewal Messages

def sendKeyRenewalRequest(peer, newPublicKey):
    # Package the key renewal request as JSON
    key_renewal_message = json.dumps({
        "type": "keyRenewalRequest",
        "newPublicKey": newPublicKey,
        "timestamp": time.time()
    })
    # Send the key renewal request using the sendData function
    sendData(peer, key_renewal_message)

def handleKeyRenewalResponse(message):
    # Parse the incoming message
    response = parseMessage(message)
    # Validate the response type
    if response.get("type") != "keyRenewalResponse":
        raise ValueError("Invalid message type for key renewal response.")
    # Return the parsed response
    return response

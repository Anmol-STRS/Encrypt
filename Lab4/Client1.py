import socket
import pickle  # Import pickle for serializing objects
from Cipher import encryptDecrypt

HOST = "127.0.0.1"
PORT = 5002

HOST = "127.0.0.1"
PORT = 5002

obj = encryptDecrypt()

client_public_key, client_private_key = obj.generate_rsa_key_pair()

symmetric_key = obj.getAAesKey()

serialized_public_key = pickle.dumps(client_public_key.export_key())
serialized_private_key = pickle.dumps(client_private_key.export_key())
serialized_symmetric_key = pickle.dumps(symmetric_key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Send both public, private, and symmetric keys to the server
    s.sendall(serialized_public_key)
    s.sendall(serialized_private_key)
    s.sendall(serialized_symmetric_key, )
    
    while True:
        msg = input("Enter message: ")  # Prompt the user for input
        
        enc_msg = obj.encryptAes(msg.encode(), symmetric_key)
        print(enc_msg)
        s.sendall(enc_msg)  # Send the encoded message to the server

        data = s.recv(1024).decode()  # Receive data from the server
        print(f"Received from server: {data}")

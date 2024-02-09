from Crypto.PublicKey import RSA
import socket
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
import base64

def encrypt_message(public_key, message):
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return base64.b64encode(ciphertext)

def decrypt_message(private_key, encrypted_message):
    cipher = PKCS1_v1_5.new(private_key)
    ciphertext = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(ciphertext, None)
    return decrypted_message.decode()

HOST = "127.0.0.1"
PORT = 5002

client_key = RSA.generate(1024)
client_public_key = client_key.publickey()
client_private_key = client_key

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Client receives the server's public key
    server_public_key_str = s.recv(1024).decode()
    server_public_key = RSA.import_key(server_public_key_str)

    while True:
        # Client encrypts a message using the server's public key
        msg = input("Enter your message: ")
        encrypted_message = encrypt_message(server_public_key, msg)
        s.sendall(encrypted_message)

        # Client receives an encrypted response from the server
        encrypted_response = s.recv(1024)
        if not encrypted_response:
            break

        # Client decrypts the response using its private key
        decrypted_response = decrypt_message(client_private_key, encrypted_response)
        print(f"Server's Response (Encrypted): {encrypted_response}")
        print(f"Decrypted Response: {decrypted_response}")

        if msg.lower() == "q":
            break

print("Connection closed.")

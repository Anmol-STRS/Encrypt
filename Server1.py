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

server_key = RSA.generate(1024)
server_public_key = server_key.publickey()
server_private_key = server_key

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()

print("Waiting for Connection..")
conn, addr = s.accept()

try:
    with conn:
        print(f"Connection from {addr}")

        # Server sends its public key to the client
        conn.sendall(server_public_key.export_key())

        while True:
            # Server receives an encrypted message from the client
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break

            # Server decrypts the message using its private key
            decrypted_message = decrypt_message(server_private_key, encrypted_message)
            print(f"Received (Encrypted): {encrypted_message}")
            print(f"Decrypted Message: {decrypted_message}")

            # Server responds by encrypting a message using the client's public key
            response = input("Enter your response: ")
            encrypted_response = encrypt_message(server_public_key, response)
            conn.sendall(encrypted_response)

except Exception as e:
    print(f"Error: {e}")

s.close()

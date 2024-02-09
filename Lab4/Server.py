import socket
import pickle
from Cipher import encryptDecrypt

HOST = "127.0.0.1"
PORT = 5002

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print(f"Waiting for Connection..")
conn, addr = s.accept()

obj = encryptDecrypt()

server_public_key, server_private_key = obj.generate_rsa_key_pair()

try:
    print(f"Connection from {addr}")

    try:
        serialized_public_key = conn.recv(2048)
        serialized_private_key = conn.recv(2048)
        serialized_symmetric_key = conn.recv(2048)

        client_public_key = pickle.loads(serialized_public_key)
        client_private_key = pickle.loads(serialized_private_key)
        symmetric_key = pickle.loads(serialized_symmetric_key)

    except pickle.UnpicklingError as e:
        print("Error during unpickling:", e)

    while True:
        data = conn.recv(1024)
        if not data:
            continue
        if data == b"q":
            break
        print(f"Received Data from Client: {data}")

        msg1 = input("Enter your response: ")
        enc_msg = obj.encrypt_rsa(msg1.encode(), client_public_key)
        conn.sendall(enc_msg)

except Exception as e:
    print(f"Exception: {e}")

finally:
    s.close()

import socket
import rsa
import rsa.randnum
import rsa.transform
import Crypto.Cipher.AES


try:
    def generate_key_pair():
        public_key, private_key = rsa.newkeys(512)  # You can adjust the key length as needed
        return public_key, private_key
    
    def generate_random_key():
        s_key, _= rsa.newkeys(1024)
        return s_key

    def encrypt_msg(msg, key):
        enc_msg = rsa.encrypt(msg.encode(), key)
        return enc_msg

    def encrypt_key(public_key, key):
        sha.
    
    def decrypt_key(enc_key, private_key):
        d_key = rsa.decrypt(enc_key, private_key)
        return d_key
    

    b = generate_random_key()
    a = encrypt_msg("Helllo", b)
    
    
    print(a)

    public_key,private_key = generate_key_pair()
    
    ec = encrypt_key(public_key, b)
    
    aa = rsa.decrypt(ec, private_key)
    
    print(aa)

except UserWarning:
    print('\n')
    print(UserWarning)
    
exit()



HOST = "127.0.0.1"
PORT = 5002

generate_key_pair()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        msg = input("Enter message (type 'q' to quit): ")  # Prompt the user for input
        s.sendall(msg.encode())  # Send the encoded message to the server

        if msg == "q":
            break  # Exit the loop if the user enters 'q'

        data = s.recv(1024).decode()  # Receive data from the server
        print(f"Received from server: {data}")

# No need to explicitly close the socket as it is handled by the 'with' statement

import socket
import rsa

HOST = "127.0.0.1" #Loopback address as the host address
PORT = 5002 #port to listen on

serverPublicKey, serverPrivateKey = rsa.newkeys(512)

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET is for IPv4

#SOCK_STREAM is used for TCP protocol
s.bind((HOST, PORT)) #.bind() method associates the socket with IP and Port
s.listen()#enables the server to accept connections
print(f"Waiting for Connection..")

while True:
    conn, addr = s.accept()
    conn.sendall(serverPublicKey.save_pkcs1())

    with conn:
        print(f"Connection from {addr}")
        client_public_key_data = conn.recv(1024)
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)

        while True:
            encr_data = conn.recv(1024)
            if not encr_data:
                break
            
            print('\n')
            print(f'Encrypted DATA: {encr_data}')
            
            print('\n')
            
            data = rsa.decrypt(encr_data, serverPrivateKey)
            print(f"DECRYPTED DATA: {data}")
            
            print('\n')

            if data == "q":
                break

            # Send a response
            response = input("Enter your response: ")
            encr_response = rsa.encrypt(response.encode(), client_public_key)
            conn.sendall(encr_response)


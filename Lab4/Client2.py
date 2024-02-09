
import socket
import rsa

HOST ="127.0.0.1"
PORT = 5002

clientPublicKey, clientPrivateKey = rsa.newkeys(512)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    serverPublicKeyData = s.recv(1024)
    serverPublicKey = rsa.PublicKey.load_pkcs1(serverPublicKeyData)
    
    while True:
        s.sendall(clientPublicKey.save_pkcs1())
        msg = input()#takes an input from the user
        encr_msg = rsa.encrypt(msg.encode(), serverPublicKey)
        print(encr_msg)
        
        s.sendall(encr_msg)#encoded message is sent to the server
        
        # Receive response from the server
        encr_data = s.recv(1024)
        decr_data = rsa.decrypt(encr_data, clientPrivateKey)
        print(f"Server response: {decr_data}")

        
        if decr_data=="q":
            break
s.close()
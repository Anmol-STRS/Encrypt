from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class encryptDecrypt:
    def getADesKey(self):
        key = get_random_bytes(8)
        return key
    def getAAesKey(self):
        key = get_random_bytes(16)
        return key
    def get_random_key(self):
        key = get_random_bytes(16)
        return key
    
    def encryptDes(self,plainText, key):
        paddedText = pad(plainText, DES.block_size)#Padding the plain text to align DES block size
        desCipher = DES.new(key, DES.MODE_ECB) #Creating the DES cipher
        return desCipher.encrypt(paddedText) #Returning the ciphered text
    
    def decryptDes(self, cipheredText, key):
        desCipher = DES.new(key, DES.MODE_ECB)
        plainText =unpad(desCipher.decrypt(cipheredText),DES.block_size)
        return plainText #Returning the plain text

    def encryptAes(self,plainText, key):
        #Update this method to complete the encryption using the AES encryption method
        paddedText = pad(plainText, AES.block_size)#Padding the plain text to align DES block size
        AesCipher = AES.new(key, AES.MODE_ECB) #Creating the DES cipher
        return AesCipher.encrypt(paddedText) #Returning the ciphered text
        

    def decryptAes(self, cipheredText, key):
        #update this method to complete the encryption using the AES descryption method
        AesCipher = AES.new(key, AES.MODE_ECB)
        plainText =unpad(AesCipher.decrypt(cipheredText),AES.block_size)
        return plainText #Returning the plain text
    
    def encryptKeys(self,key1, key2):
        paddedText = pad(key1, AES.block_size)#Padding the plain text to align DES block size
        AesCipher = AES.new(key2, AES.MODE_ECB) #Creating the DES cipher
        return AesCipher.encrypt(paddedText) #Returning the ciphered text
    
    def encrypt_rsa_key_with_aes(self, aes_key, rsa_key):
        serialized_rsa_key = rsa_key.export_key()  # Serialize the RSA key
        padded_rsa_key = pad(serialized_rsa_key, AES.block_size)
        aes_cipher = AES.new(aes_key, AES.MODE_ECB)  # Create AES cipher
        encrypted_rsa_key = aes_cipher.encrypt(padded_rsa_key)  # Encrypt RSA key with AES
        return encrypted_rsa_key
    
    
    def decrypt_rsa_key_with_aes(self, private_key, encrypted_rsa_key): 
        serialized_rsa_key = private_key.export_key()  # Serialize the RSA key
        padded_private_rsa_key = pad(serialized_rsa_key, AES.block_size)
        aes_cipher = AES.new(padded_private_rsa_key, AES.MODE_ECB)  # Create AES cipher
        decrypted_rsa_key = aes_cipher.decrypt(encrypted_rsa_key)  # Decrypt RSA key with AES
        unpadded_rsa_key = unpad(decrypted_rsa_key, AES.block_size)  # Remove padding
        return unpadded_rsa_key
    
    def encrypt_aes_key_with_rsa(self, aes_key, rsa_public_key):
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        return encrypted_aes_key
    
    def decrypt_aes_key_with_rsa(self, encrypted_aes_key, rsa_private_key):
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        return decrypted_aes_key
    
    def generate_rsa_key_pair(self):
        key = RSA.generate(1024)  
        return key.publickey(), key
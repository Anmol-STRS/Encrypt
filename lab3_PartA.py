from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
from base64 import b64decode
 
class encryptDecrypt:
#if you need to add more methods feel free to add them
    def getADesKey(self):
        key = get_random_bytes(8)
        return key
    def getAAesKey(self):
        key = get_random_bytes(16)
        return key
    
    def getShaKey(self):
        key = get_random_bytes(2000)
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
        
objEncrypt = encryptDecrypt() #An object of encryptDecrypt() class is created
encryptionKey= objEncrypt.getADesKey() #A random DES key is generated
encryptionKey1 = objEncrypt.getAAesKey(); #Gets random AES KEY
plainText = b'Python is a very powerful language' #Plain text to be encrypted

print('');

#Encryption using DES algorithm
encryptedText = objEncrypt.encryptDes(plainText,encryptionKey)
encryptedText = b64encode(encryptedText).decode('utf-8')
print("Encrypted Text from DES: {}".format(encryptedText));

#Decryption using DES algorithm
decodedEncryptedText= b64decode(encryptedText)
decryptedText = objEncrypt.decryptDes(decodedEncryptedText,encryptionKey)
print('Decrypted Text(Used Des): {}'.format(decryptedText))

print('');

#Encryption using AES algorithm
encryptedText1 = objEncrypt.encryptAes(plainText,encryptionKey1)
encryptedText1 = b64encode(encryptedText1).decode('utf-8')
print("Encrypted Text from AES: {}".format(encryptedText1));


#Decryption using AES algorithm
decodedEncryptedText1= b64decode(encryptedText1)
decryptedText1 = objEncrypt.decryptAes(decodedEncryptedText1,encryptionKey1)
print('Decrypted Text(Used Aes): {}'.format(decryptedText))



# needs pycryptodome (pip install pycryptodomex)
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
from Cryptodome.Hash import CMAC, SHA

class PyPaceCrypto:

    def decryptBlock(self, key, ciphertext):
        aes = AES.new(str(key), AES.MODE_ECB)
        return bytearray(aes.decrypt(str(ciphertext)))
        
    def encryptBlock(self, key, plaintext):
        aes = AES.new(str(key), AES.MODE_ECB)
        return bytearray(aes.encrypt(str(plaintext)))

    def decrypt(self, key, ssc, ciphertext):
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(str(key), AES.MODE_CBC, str(iv))
        paddedCiphertext = self.aes.decrypt(ciphertext)
        return bytearray(self.addPadding(str(paddedCiphertext)))

    def encrypt(self, key, ssc, plaintext):
        iv = self.encryptBlock(key, ssc)
        aes = AES.new(str(key), AES.MODE_CBC, str(iv))
        paddedPlaintext = self.addPadding(str(plaintext))
        return bytearray(aes.encrypt(paddedPlaintext))

    def getMAC(self, key, ssc, data):
        n = ssc + data
        paddedn = self.addPadding(n)
        cmac = CMAC.new(str(key), ciphermod=AES)
        cmac.update(paddedn)
        return bytearray(cmac.digest())
    
    def getCMAC(self, key, data):
        cmac = CMAC.new(str(key), ciphermod=AES)
        cmac.update(str(data))
        return bytearray(cmac.digest())

    def kdf(self, password, c):
        intarray = [0, 0, 0 , c]
        mergedData = list(bytearray(password)) + intarray
        sha = SHA.new()
        sha.update(bytearray(mergedData))
        return bytearray(sha.digest())[0:16]
    
    def addPadding(self, data):
        return Padding.pad(str(data), AES.block_size, style='iso7816')

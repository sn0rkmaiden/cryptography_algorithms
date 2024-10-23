import hashlib
import numpy as np

class FeistelCipher:    

    def __init__(self, blocksize, secret, num_rounds):
        self.blocksize = blocksize
        self.secret = secret
        self.rounds = num_rounds

    def encrypt(self, key, message, mode='ecb'):
        n = self.blocksize
        message = [message[i:i+n] for i in range(0, len(message), n)]
        lastBlock = len(message[-1])        
        # padding 
        if (lastBlock < n):
            for i in range(lastBlock, n):
                message[-1] += ' '
        key = hashlib.sha256(str(key + self.secret).encode('utf-8')).hexdigest()        
        ciphertext = ""
        for block in message:
            L = [""] * (self.rounds + 1)
            R = [""] * (self.rounds + 1)

            L[0] = block[0:n//2]
            R[0] = block[n//2:n]

            for i in range(1, n + 1):
                L[i] = R[i - 1]                
                R[i] = self.xor(L[i - 1], self.scramble(R[i - 1], i, key))
            
            ciphertext += (L[n] + R[n])
        return ciphertext

    def decrypt(self, key, ciphertext, mode='ecb'):        
        n = self.blocksize
        ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]
        lastBlock = len(ciphertext[-1])        
        # padding 
        if (lastBlock < n):
            for i in range(lastBlock, n):
                ciphertext[-1] += ' '

        key = hashlib.sha256((key + self.secret).encode('utf-8')).hexdigest()        
        message = ""
        for block in ciphertext:
            L = [""] * (self.rounds + 1)
            R = [""] * (self.rounds + 1)

            L[self.rounds] = block[0:n//2]    
            R[self.rounds] = block[n//2:n]

            for i in range(8, 0, -1):                
                R[i - 1] = L[i]                
                L[i - 1] = self.xor(R[i], self.scramble(L[i], i, key))
            
            message += (L[0] + R[0])
        return message


    def xor(self, s1, s2):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

    def subkeygen(self, s1, s2, i):
        return hashlib.sha256(str(s1 + s2).encode('utf-8')).hexdigest()
    
    def scramble(self, x, i, k):
        k = self.stobin(k)
        x = self.stobin(str(x))

        k = self.bintoint(k)
        x = self.bintoint(x)

        res = pow((x * k), i)
        res = self.itobin(res)

        return self.bintostr(res)
    
    # string to binary
    def stobin(self, s):
        return ''.join('{:08b}'.format(ord(c)) for c in s)


    # binary to int
    def bintoint(self, s):
        return int(s, 2)


    # int to binary
    def itobin(self, i):
        return bin(i)


    # binary to string
    def bintostr(self, b):        
        return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))


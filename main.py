from feistel import FeistelCipher


fc = FeistelCipher(8, "secret", 8)
original_message = "This is my message"
ciphertext = fc.encrypt("feistel", original_message)
print(ciphertext.encode('utf-8'))
message = fc.decrypt("feistel", ciphertext=ciphertext)
print(message)
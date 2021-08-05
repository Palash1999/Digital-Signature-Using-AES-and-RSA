# Palash Rathore - 2018173
import socket
from rsaEncrypt import *
from rsaDecrypt import *
from sAES_Encryption import sAES_E
import hashlib

# binary to decimal function


def binaryToDecimal(binary):
    return binary


print("Palash Rathore - 2018173")

# connecting
s = socket.socket()
port = 31313
s.connect(('localhost', port))


# reciecing key from server
data = (s.recv(1024).decode())

strData = data.split(",")
server_e = int(strData[0])
server_n = int(strData[1])

print("Server's public key fetched!")

message = int(input("Input Message : "), 2)
key = int(input("Secret Key : "), 2)

ce, cn = map(int, input("Public key parameters : (e, n) ").split())
cd, cn = map(int, input("Private key parameters : (d, n) ").split())

# hash algo
mess = str(message)
mDigest = hashlib.md5((mess).encode())
message_digest = mDigest.hexdigest()

cipher = sAES_E(key).encrypt(message)
sendData = str(cipher) + ',' + str(key)


secret_key = binaryToDecimal(key)
encrypted_secret_key = encrypt(server_e, server_n, secret_key)
int_mes_dig = int(message_digest, 16)

# Encrypting using RSA
signature = encrypt(ce, cn, int_mes_dig)

print("Encrypted secret key : ", encrypted_secret_key)
print("Cipher text : ", cipher)
print("Digest : ", message_digest)
print("Digital Signature : ", signature)

# Sending data to server
sendData = str(cipher) + ',' + str(encrypted_secret_key) + ',' + \
    str(signature) + ',' + str(ce) + ',' + str(cn)
s.send(bytes(sendData, 'utf-8'))
print(s.recv(1024).decode())
s.close()

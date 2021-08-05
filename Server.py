# Palash Rathore - 2018173
import socket
from rsaEncrypt import *
from rsaDecrypt import *
from sAES_Decryption import sAES_D
import hashlib


def binaryToDecimal(binary):
    return binary


def DecimalToBinary(n):
    return bin(n).replace("0b", "")


s = socket.socket()
print("Palash Rathore - 2018173")
print("Connection Created!")
port = 31313
s.bind(('localhost', port))
s.listen(3)


while True:
    c, addr = s.accept()

    # sending public key to client
    server_e, server_n = map(int, input(
        "Public key parameters : (e , n) ").split())
    public_key = str(server_e) + ',' + str(server_n)
    c.send(bytes(public_key, 'utf-8'))

    server_d, server_n = map(int, input(
        "Private key parameter : (d, n) ").split())

    # recieving Data from client
    data = c.recv(1024).decode("utf-8")
    strData = data.split(",")

    ciphertext = int(strData[0])
    enc_key = int(strData[1])
    signature = int(strData[2])
    ce = int(strData[3])
    cn = int(strData[4])

    # Decryption key
    server_private = (server_d, server_n)

    # Using RSA decrypt for secret key
    decrypted_key = decrypt(server_d, server_n, enc_key)
    D_key = DecimalToBinary(decrypted_key)
    print("Decrypted key : ", D_key)

    # Getting message using AES
    plaintext = sAES_D(decrypted_key).decrypt(ciphertext)
    print("Decrypted Message : ", bin(plaintext)[2:])

    # inbuilt hash algo for message digest
    mess = str(plaintext)
    mDigest = hashlib.md5((mess).encode())
    message_digest = mDigest.hexdigest()
    print("Message Digest : ", message_digest)

    int_message_dig = int(message_digest, 16)
    sign = encrypt(ce, cn, int_message_dig)
    print("Client's Signature : ", signature)
    print("Intermediate Verifcation Code : ", sign)

    # To check signature verification
    if signature == sign:
        print("Signature Verified")
    else:
        print("Signature Not Verified")

    c.close()

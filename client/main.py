import socket
from Cryptodome.Cipher import AES
import binascii
from Cryptodome.Util.Padding import unpad


BLOCK_SIZE = 128
Q_BLOCKS = 1000
HOST = '127.0.0.1'
PORT = 65432
K3 = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')
cipher = AES.new(K3, AES.MODE_ECB)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def aes_ofb_mode(s):
    K2 = cipher.decrypt(s.recv(16))
    IV = cipher.decrypt(s.recv(128))

    l = s.recv(128)
    plainL, nextIV = aes_ofb(l, IV, K2)
    f.write(plainL)
    l = s.recv(128)
    q_index = 2
    while l:
        plainL, IV = aes_ofb(l, nextIV, K2)
        nextIV = IV
        f.write(plainL)
        if q_index == Q_BLOCKS:
            q_index = 0
            K2 = cipher.decrypt(s.recv(16))
            nextIV = cipher.decrypt(s.recv(128))

            print(K2)

        l = s.recv(128)
        q_index += 1



def aes_ofb(l, IV, K2):
    dec_cipherK2 = AES.new(K2, AES.MODE_ECB)
    new_IV = dec_cipherK2.encrypt(IV)
    return byte_xor(l, new_IV), new_IV



def aes_cbc_mode(s):
    K1 = cipher.decrypt(s.recv(16))
    IV = cipher.decrypt(s.recv(128))

    l = s.recv(256)
    plainL, nextIV = aes_cbc(l, IV, K1)
    f.write(plainL)
    l = s.recv(256)
    q_index = 2

    while l:
        plainL, IV = aes_cbc(l, nextIV, K1)
        nextIV = IV
        f.write(plainL)
        if q_index == Q_BLOCKS:
            q_index = 0
            K1 = cipher.decrypt(s.recv(16))
            nextIV = cipher.decrypt(s.recv(128))
            print(K1)

        l = s.recv(256)
        q_index += 1



def aes_cbc(l, IV, K1):
    dec_cipherK1 = AES.new(K1, AES.MODE_ECB)
    new_l = unpad(dec_cipherK1.decrypt(l), BLOCK_SIZE)
    return byte_xor(new_l, IV), l


f = open('iii.jpg', 'wb')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'Connection made.')

    mode = s.recv(16)
    if mode == b'OFB':
        aes_ofb_mode(s)
    elif mode == b'CBC':
        aes_cbc_mode(s)

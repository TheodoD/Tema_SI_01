import socket
from Cryptodome.Cipher import AES
import binascii
import os


BLOCK_SIZE = 128
Q_BLOCKS = 100
HOST = '127.0.0.1'
PORT = 65433
K3 = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')
K1 = os.urandom(16)
K2 = os.urandom(16)
IV = os.urandom(128)
cipher = AES.new(K3, AES.MODE_ECB)



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        data = conn.recv(16)
        while True:
            mode = conn.recv(16)
            if mode == b'CBC':
                print(K1)
                conn.sendall(cipher.encrypt(K1))
                conn.sendall(cipher.encrypt(IV))
                K1 = os.urandom(16)
                IV = os.urandom(128)
            elif mode == b'OFB':
                print(K2)
                conn.sendall(cipher.encrypt(K2))
                conn.sendall(cipher.encrypt(IV))
                K2 = os.urandom(16)
                IV = os.urandom(128)
            elif mode == b'exit':
                break

        conn.shutdown(socket.SHUT_WR)

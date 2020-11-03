import socket
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import binascii


BLOCK_SIZE = 128
Q_BLOCKS = 1000
HOST = '127.0.0.1'
PORT = 65432
PORTKM = 65433
K3 = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')
cipher = AES.new(K3, AES.MODE_ECB)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def aes_ofb_mode(conn, IV, K2, sKM):
    cipherK2 = cipher.encrypt(K2)
    cipherIV = cipher.encrypt(IV)
    conn.sendall(cipherK2)
    conn.sendall(cipherIV)

    l = f.read(128)
    cipherL, nextIV = aes_ofb(l, IV, K2)
    conn.send(cipherL)
    q_index = 1

    l = f.read(128)

    while l:
        if q_index == Q_BLOCKS:
            q_index = 0
            sKM.sendall(b'OFB')
            enc_K2 = sKM.recv(16)
            enc_nextIV = sKM.recv(128)
            K2 = cipher.decrypt(enc_K2)
            nextIV = cipher.decrypt(enc_nextIV)
            conn.sendall(enc_K2)
            conn.sendall(enc_nextIV)
            print(K2)

        cipherL, IV = aes_ofb(l, nextIV, K2)
        conn.send(cipherL)
        q_index += 1
        nextIV = IV
        l = f.read(128)


def aes_ofb(l, IV, K2):
    cipher1 = AES.new(K2, AES.MODE_ECB)
    enc_block = cipher1.encrypt(IV)
    new_l = byte_xor(l, enc_block)
    return new_l, enc_block


def aes_cbc_mode(conn, IV, K1, sKM):
    cipherK1 = cipher.encrypt(K1)
    conn.sendall(cipherK1)
    conn.sendall(cipher.encrypt(IV))

    l = f.read(128)
    cipherL, nextIV = aes_cbc(l, IV, K1)
    conn.send(cipherL)
    q_index = 1
    l = f.read(128)

    while l:
        if q_index == Q_BLOCKS:
            q_index = 0
            sKM.sendall(b'CBC')
            enc_K1 = sKM.recv(16)
            enc_nextIV = sKM.recv(128)
            K1 = cipher.decrypt(enc_K1)
            nextIV = cipher.decrypt(enc_nextIV)
            conn.sendall(enc_K1)
            conn.sendall(enc_nextIV)
            print(K1)

        cipherL, IV = aes_cbc(l, nextIV, K1)
        conn.send(cipherL)
        q_index += 1
        nextIV = IV
        l = f.read(128)


def aes_cbc(l, IV, K1):
    cipher1 = AES.new(K1, AES.MODE_ECB)
    new_l = byte_xor(l, IV)
    return cipher1.encrypt(pad(new_l, BLOCK_SIZE)), cipher1.encrypt(pad(new_l, BLOCK_SIZE))


f = open('ide.jpg', 'rb')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sKM:
    sKM.connect((HOST, PORTKM))
    sKM.sendall(b'Connection made.')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(16)
                if not data:
                    break

                while True:
                    aes_mode = input('Enter the mode for encrytion: ')
                    if aes_mode == 'OFB':
                        conn.sendall(b'OFB')
                        sKM.sendall(b'OFB')
                        K2 = cipher.decrypt(sKM.recv(16))
                        IV = cipher.decrypt(sKM.recv(128))
                        aes_ofb_mode(conn, IV, K2, sKM)
                        sKM.sendall(b'exit')
                        break
                    elif aes_mode == 'CBC':
                        conn.sendall(b'CBC')
                        sKM.sendall(b'CBC')
                        K1 = cipher.decrypt(sKM.recv(16))
                        IV = cipher.decrypt(sKM.recv(128))
                        aes_cbc_mode(conn, IV, K1, sKM)
                        sKM.sendall(b'exit')
                        break
                    else:
                        print('Invalid mode.')

                conn.shutdown(socket.SHUT_WR)

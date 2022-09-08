import rsa
from os.path import exists
from os import mkdir
import math
import base64
from Crypto.Cipher import AES
from cryptography import *

PRIV_PROG_KEY_NAME = 'prog_private_key.pem'
PUB_PROG_KEY_NAME = 'prog_publick_key.pem'


def check_secure_programm_key(file=PRIV_PROG_KEY_NAME):
    if not exists(file): generate_program_keys()


def generate_program_keys():
    (pubkey, privkey) = rsa.newkeys(512)

    with open(PRIV_PROG_KEY_NAME, 'wb') as f:
        f.write(privkey.save_pkcs1())

    with open(PUB_PROG_KEY_NAME, 'wb') as f:
        f.write(pubkey.save_pkcs1())


def padding_aes(word):
    return word + word[:16 - len(word)]


def aes_pincode():
    password = input("Enter a password (8-16 characters): ")
    password = password.encode('utf-8')

    if len(password) > 16 or len(password) < 8:
        print("Incorrect password")
        raise SystemExit

    return padding_aes(password)


def save_privkey(privkey, key, login):
    cipher = AES.new(key, AES.MODE_EAX)
    privkey = b'.|.'.join(privkey)
    ciphertext, tag = cipher.encrypt_and_digest(privkey)

    with open(login + '/priv_key', 'wb') as f: 
        [ f.write(x) for x in (cipher.nonce, tag, ciphertext) ]


def registration():
    login = input("Please, enter your login: ")
    pin = aes_pincode()
    pub_key, priv_key = generate_keys()

    with open(PRIV_PROG_KEY_NAME, 'rb') as f: 
        keydata = f.read()

    priv_prog_key = rsa.PrivateKey.load_pkcs1(keydata)
    hash = rsa.compute_hash(pub_key, 'SHA-256')
    signature = rsa.sign_hash(hash, priv_prog_key, 'SHA-256')
    pub_key += b'.|.' + signature

    if not exists(login):
        mkdir(login)
        save_privkey(priv_key, pin, login)
        with open(login + '/pub_key', 'wb') as f: f.write(pub_key)


def encryption():
    path = input("Enter the path with public key: ")
    passwd = input("Enter password (8-75 characters): ")

    if len(passwd) > 75 or len(passwd) < 8:
        print("Incorrect password")
        raise SystemExit

    if not exists(path): 
        print('-'*20, '\nError: Public key not found')
        raise SystemExit

    with open(path, 'rb') as f: pubkey, sign = f.read().split(b'.|.')
    with open(PUB_PROG_KEY_NAME, 'rb') as f: 
        keydata = f.read()
        prog_pubkey = rsa.PublicKey.load_pkcs1(keydata) 

    pubkey_copy = pubkey
    sign = rsa.verify(pubkey_copy, sign, prog_pubkey)
    number = int.from_bytes(passwd.encode('utf-8'), "big", signed=False)
    cipher = str(encryption(number, int(pubkey))).encode('utf-8')

    return base64.b32encode(cipher).decode('utf-8')


def read_privkey(key, path):
    with open(path, 'rb') as f:
        nonce, tag, ciphertext = [ f.read(x) for x in (16, 16, -1) ]

    key = padding_aes(key).encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    return data

def decrypt():
    path = input("Enter the path with private key: ")
    passwd = input("Enter ciphered password: ")
    pin = input("Enter a password: ")

    p, q = read_privkey(pin, path).split(b'.|.')
    passwd = base64.b32decode(passwd.encode('utf-8'))
    dechifr = decryption(int(passwd), int(p), int(q))
    bytes_required = max(1, math.ceil(dechifr.bit_length() / 8))
    raw = dechifr.to_bytes(bytes_required, "big")

    return raw.decode("utf-8")


flag = True
if len(sys.argv) > 1: 
    mode = sys.argv[1]
else:
    mode = input("Select the operating mode: reg, enc, dec: ")

while (flag == True):
    if __name__ == "__main__":
        check_secure_programm_key()
        if mode == "reg":
            flag = False
            registration()
        elif mode == "enc":
            flag = False
            print(encryption())
        elif mode == "dec":
            flag = False
            print(decrypt())
        else:
            mode = input("unknown command, repeat input: ")
import base64
import hashlib
import os
from typing import List
import password
import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import file_manager
import json
import time
from logger import make_log, LogMessage

metadata = {
    "mode": 0,
    "key_length": 0,
    "login": "",
    "password_hash": "",
    "random_number": bytes(0), #in b64
    "crc": 0
    #"salt": bytes(0)
}

rsa_password = [int(format(ord('d'))) ^ 1, int(format(ord('#'))) ^ 2, int(format(ord('R'))) ^ 3, int(format(ord('2'))) ^ 4,
                int(format(ord('O'))) ^ 5, int(format(ord('x'))) ^ 6, int(format(ord('d'))) ^ 7, int(format(ord('T'))) ^ 8]
print(rsa_password)
count = 1
for dat in rsa_password:
    out = dat ^ count
    print(chr(out))
    count += 1


def generate_number(byte_length):
    return os.urandom(byte_length)


def run_integrity_check():
    if check_blockchain() and check_crc() and check_hash():
        return True
    return False


def derive_key(master_password, key_length, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=key_length,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    return kdf.derive(master_password.encode('utf-8'))


def check_blockchain(unchecked_list: List[password.Password]):
    prev_hash = ""
    for block in unchecked_list:
        if block.hash != block.calculate_hash() or block.previous_hash != prev_hash:
            return False
        prev_hash = block.hash
    return True


def check_crc():
    return None


def check_hash():
    return None


def encrypt_database(encoded_database: [{}], algorithm, key_length, master_password):
    return None


def decrypt_database(encrypted_database, algorithm, key_length, master_password):
    return None


def aes_gcm_encrypt(database: [{}], key_length, master_password):
    salt = generate_number(16)
    nonce = generate_number(24)

    padder = padding.PKCS7(128).padder()
    padded_database = padder.update(database) + padder.finalize()

    cipher = Cipher(algorithms.AES(derive_key(master_password, key_length, salt)), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    return [encryptor.update(padded_database) + encryptor.finalize(), nonce, salt]




def prepare_metadata(master_password):
    metadata_to_save = metadata
    metadata_to_save["random_number"] = encrypt_random_number(generate_number(32), master_password)
    return metadata_to_save


def encode_metadata(metadata_list: {}, master_password):
    global metadata
    metadata = metadata_list
    metadata["random_number"] = decrypt_random_number(metadata_list["random_number"], master_password)


def encrypt_random_number(rnd_number, master_password):
    print(rnd_number)
    cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(master_password.encode('utf-8')).hexdigest())), modes.ECB())
    encryptor = cipher.encryptor()
    return base64.b64encode(encryptor.update(rnd_number) + encryptor.finalize()).decode('utf-8')


def decrypt_random_number(encrypted_number, master_password):
    cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(master_password.encode('utf-8')).hexdigest())), modes.ECB())
    decryptor = cipher.decryptor()
    return base64.b64encode(decryptor.update(base64.b64decode(encrypted_number)) + decryptor.finalize())


def encrypt_metadata(metadata_to_save: {}):
    public_key = serialization.load_pem_public_key(file_manager.open_file(utils.FilePath.public.value), backend=default_backend())
    return public_key.encrypt(json.dumps(metadata_to_save).encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                                         algorithm=hashes.SHA256(),
                                                                                         label=None))


def decrypt_metadata(metadata_from_file):
    private_key = serialization.load_pem_private_key(file_manager.open_file(utils.FilePath.private.value),
                                                     backend=default_backend(),
                                                     password=len(rsa_password).to_bytes(byteorder='big', length=16))
    decrypted_message = private_key.decrypt(metadata_from_file, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                             algorithm=hashes.SHA256(),
                                                                             label=None))
    return json.loads(decrypted_message.decode('utf-8'))


def save_metadata(master_password):
    file_manager.write_file(encrypt_metadata(prepare_metadata(master_password)), utils.FilePath.metadata.value)


def load_metadata(master_password):
    encode_metadata(decrypt_metadata(file_manager.open_file(utils.FilePath.metadata.value)), master_password)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    file_manager.write_file(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.BestAvailableEncryption(
                                                          len(rsa_password).to_bytes(byteorder='big', length=16))),
                            utils.FilePath.private.value)
    file_manager.write_file(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo),
                            utils.FilePath.public.value)


make_log(LogMessage.app_started.value)
time1 = time.time()
make_log(LogMessage.encryption_start.value)
generate_rsa_keys()
save_metadata("silneheslo")
make_log("Encryption ended")
load_metadata("silneheslo")
make_log(LogMessage.decryption_finish.value)
time2 = time.time()
print(metadata)
print(base64.b64decode(metadata["random_number"]))
print(time2-time1)

import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class PasswordBlueprint:
    def __init__(self, url, password):
        self.url = url
        self.password = password


class Password(PasswordBlueprint):
    def __init__(self, url, password, previous_hash):
        super().__init__(url, password)
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        cache_str = self.url + self.password + self.previous_hash + str(self.timestamp)
        return hashlib.sha256(cache_str.encode("utf-8")).hexdigest()

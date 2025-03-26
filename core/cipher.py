import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes

class Cipher:
    def __init__(self, key: bytes, algorithm: str = "AES"):
        """
        Initializes the Cipher class with a given encryption key and algorithm.

        Args:
            key (bytes): The secret key for encryption and decryption.
            algorithm (str): The encryption algorithm to use ("AES" or "CHACHA20").
        """
        self.algorithm = algorithm.upper()

        if self.algorithm == "AES":
            self.key = self._adjust_key(key, [16, 24, 32])
        elif self.algorithm == "CHACHA20":
            self.key = self._adjust_key(key, [32])
        else:
            raise ValueError("Unsupported encryption algorithm")

    def encrypt(self, data: bytes) -> str:
        """Encrypts the given data using the selected algorithm."""
        if self.algorithm == "AES":
            return self._encrypt_aes(data)
        elif self.algorithm == "CHACHA20":
            return self._encrypt_chacha20(data)
        else:
            raise ValueError("Unsupported encryption algorithm")

    def decrypt(self, enc_data: str) -> bytes:
        """Decrypts the given encrypted data."""
        enc_dict = json.loads(b64decode(enc_data).decode())
        if enc_dict["algorithm"] == "AES":
            return self._decrypt_aes(enc_dict)
        elif enc_dict["algorithm"] == "CHACHA20":
            return self._decrypt_chacha20(enc_dict)
        else:
            raise ValueError("Unsupported decryption algorithm")

    def encrypt_file(self, input_file: str, output_file: str = ""):
        """Encrypts a file and saves the encrypted content with a custom header."""
        with open(input_file, "rb") as f:
            data = f.read()
        encrypted_data = self.encrypt(data)

        if not output_file:
            output_file = input_file + ".acrypt"  # Yangi maxsus kengaytma

        with open(output_file, "w") as f:
            f.write("A-Crypt\n")  # Maxsus identifikator qo'shamiz
            f.write(encrypted_data)

    def decrypt_file(self, input_file: str, output_file: str = ""):
        """Decrypts a file only if it has the correct header."""
        with open(input_file, "r") as f:
            lines = f.readlines()

        if not lines or lines[0].strip() != "A-Crypt":
            print("🚫 Error: This file is not an A-Crypt encrypted file!")
            return  # Agar fayl noto‘g‘ri bo‘lsa, chiqamiz

        encrypted_data = "".join(lines[1:])  # Haqiqiy shifrlangan ma'lumot
        decrypted_data = self.decrypt(encrypted_data)

        if not output_file:
            output_file = input_file.replace(".acrypt", "")

        with open(output_file, "wb") as f:
            f.write(decrypted_data)
    def _encrypt_aes(self, data: bytes) -> str:
        """Encrypts data using AES algorithm (CBC mode)."""
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = self._pad(data)
        encrypted_bytes = cipher.encrypt(padded_data)
        enc_dict = {
            "algorithm": "AES",
            "iv": b64encode(iv).decode(),
            "ciphertext": b64encode(encrypted_bytes).decode()
        }
        return b64encode(json.dumps(enc_dict).encode()).decode()

    def _decrypt_aes(self, enc_dict: dict) -> bytes:
        """Decrypts AES-encrypted data."""
        iv = b64decode(enc_dict["iv"])
        ciphertext = b64decode(enc_dict["ciphertext"])
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return self._unpad(decrypted_data)

    def _encrypt_chacha20(self, data: bytes) -> str:
        """Encrypts data using ChaCha20 algorithm."""
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        encrypted_bytes = cipher.encrypt(data)
        enc_dict = {
            "algorithm": "CHACHA20",
            "nonce": b64encode(nonce).decode(),
            "ciphertext": b64encode(encrypted_bytes).decode()
        }
        return b64encode(json.dumps(enc_dict).encode()).decode()

    def _decrypt_chacha20(self, enc_dict: dict) -> bytes:
        """Decrypts ChaCha20-encrypted data."""
        nonce = b64decode(enc_dict["nonce"])
        ciphertext = b64decode(enc_dict["ciphertext"])
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        return cipher.decrypt(ciphertext)

    def _pad(self, data: bytes) -> bytes:
        """Applies PKCS7 padding to the data for AES encryption."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Removes PKCS7 padding from decrypted data."""
        return data[:-data[-1]]

    def _adjust_key(self, key, valid_lengths):
        """Adjust key to a valid length by padding or truncating."""
        key = key.encode()  # Ensure key is bytes
        if len(key) in valid_lengths:
            return key
        return key.ljust(min(valid_lengths), b' ')[:min(valid_lengths)]
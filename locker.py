from cryptography.fernet import Fernet
import os


class Cs404_locker:
    def __init__(self):
        self.key = None

    # Used to generate an encryption key given a path and key name
    def generate_key(self, path, key_name):
        self.key = Fernet.generate_key()
        extension = ".404key"
        final_key = key_name + extension
        key_place = os.path.join(path, final_key)
        with open(key_place, "wb") as file:
            file.write(self.key)

    # Used to load a key from a file
    def load_key(self, key_path):
        if self.key is None:
            with open(key_path, "rb") as file:
                self.key = file.read()
        return self.key

    # Used to encrypt the specified file
    def encrypt_file(self, file_name, encrypt_key):
        if self.key is not None:
            key_file = self.load_key()
        else:
            key_file = self.load_key(encrypt_key)
        fernet = Fernet(key_file)

        # Reads original file
        with open(file_name, "rb") as file:
            file_data = file.read()

        # Encrypts data
        encrypted_data = fernet.encrypt(file_data)

        # Writes out encrypted data file with .404 extension
        with open(file_name, "wb") as file:
            file.write(encrypted_data)
            file.close()
            extension = ".404"
            new_name = file_name + extension
            os.rename(file_name, new_name)

    # Decrypts a file with a key
    def decrypt_file(self, file_name, encrypt_key):

        # Loads the encryption key
        if self.key is not None:
            key_file = self.load_key()
        else:
            key_file = self.load_key(encrypt_key)
        fernet = Fernet(key_file)

        # Reads encrypted data
        with open(file_name, "rb") as file:
            encrypted_data = file.read()

        # Decrypts Data
        decrypted_data = fernet.decrypt(encrypted_data)

        # Writes file back out witout .404 extension
        with open(file_name, "wb") as file:
            file.write(decrypted_data)
            file.close()
            os.rename(file_name, os.path.splitext(file_name)[0])

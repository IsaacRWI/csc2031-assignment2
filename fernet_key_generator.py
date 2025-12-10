from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(key.decode())
# for generating fernet key in .env for encrypting bio
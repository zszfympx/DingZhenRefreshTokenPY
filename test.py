from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode

def get_initialization_vector(secret_key):
    # 将SecretKey字符串解码为字节
    key_bytes = b64decode(secret_key)
    # 取前16字节作为IV
    return key_bytes[:16]

def encrypt(plaintext, secret_key):
    # 将SecretKey字符串解码为字节
    key_bytes = b64decode(secret_key)
    iv = get_initialization_vector(secret_key)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 使用PKCS7填充
    encrypted_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    # 返回Base64编码的加密数据
    return b64encode(encrypted_bytes).decode()

def decrypt(ciphertext, secret_key):
    # 将SecretKey字符串解码为字节
    key_bytes = b64decode(secret_key)
    iv = get_initialization_vector(secret_key)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # Base64解码后解密数据，并移除填充
    decrypted_bytes = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return decrypted_bytes.decode()

# 示例使用
secret_key = "tg8DRuZZc9rAxrQgqDx/IuTa0ZgDogZ1cIxAO1udGPg="
plaintext = "Hello World"

encrypted = encrypt(plaintext, secret_key)
print("Encrypted:", encrypted)

decrypted = decrypt('mTGghrlkkgAT0AqUACu8ew==', secret_key)
print("Decrypted:", decrypted)

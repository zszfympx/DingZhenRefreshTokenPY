from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import requests
from base64 import b64decode, b64encode
import yaml
import random
import time

app = Flask(__name__)

config: dict = None
with open('./config.yml', 'r', encoding='utf-8') as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)
print(config)
lastAuthTime: int = int(int(time.time())-int(config['gateway']['colddown']))

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

def getAccount() -> dict:
    acc :list = str(random.choice(config['accounts'])).split('-')
    username = acc[0]
    password = acc[1]
    hwid = acc[2]
    return {'username': username, 'password': password, 'hwid': hwid}

def doAuth(account: dict) -> dict:
    global lastAuthTime
    url = "http://www.vape.gg/auth.php"
    headers = {
        "User-Agent": f"Agent_{account['hwid']}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "email": account['username'],
        "password": account['password'],
        "hwid": account['hwid'],
        "v": "v3",
        "t": "true"
    }
    lastAuthTime = int(time.time())
    try:
        response = requests.post(url, headers=headers, data=data)

        if response.text:
            response_string = response.text.strip()

            if response.ok:
                if len(response_string) != 33:

                    if response_string == "1006":
                        return {'token': 'null', 'status': 'CLOUDFLARE', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}
                        
                    elif response_string == "102":
                        return {'token': 'null', 'status': 'BANNED', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}
                        
                    else:
                        return {'token': 'null', 'status': 'SERVLET_ERROR', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}

            return {'token': encrypt(response.text, config['gateway']['secret_key']), 'status': 'OK', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}
        else:
            return {'token': 'null', 'status': 'SERVLET_ERROR', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}

    except Exception:
        return {'token': 'null', 'status': 'SERVLET_ERROR', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}     

@app.route("/")
def pong():
    return "DingZhenRefreshPY(https://github.com/zszfympx/DingZhenRefreshPY)"

@app.route("/gateway/token")
def refresh_token():
    global lastAuthTime
    sending_secret = request.headers['X-Gateway-Secret']
    try:
        if not decrypt(sending_secret, config['gateway']['secret_key']) == 'Hello World':
            return 'Gateway Secret is not correct.', 403
    except Exception:
        return 'Gateway Secret is not correct.', 403
    if int(lastAuthTime+config['gateway']['colddown'])>int(time.time()):
        print(int(lastAuthTime+config['gateway']['colddown']), int(time.time()))
        return {'token': 'null', 'status': 'NO_ACCOUNT', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}, 200
    return doAuth(getAccount()), 200

@app.route("/gateway/heartbeat")
def heartbeat():
    global lastAuthTime
    sending_secret = request.headers['X-Gateway-Secret']
    print(sending_secret)
    print(config['gateway']['secret_key'])
    try:
        if not decrypt(sending_secret, config['gateway']['secret_key']) == 'Hello World':
            return 'Gateway Secret is not correct.', 403
    except Exception:
        return 'Gateway Secret is not correct.', 403
    return {'time': time.time(), 'colddown': {'time': lastAuthTime-config['gateway']['colddown']}, 'implementation': 'zszfympx/DingZhenRefreshTokenPY'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2333)     
from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import requests
import base64
import yaml
import random
import time

app = Flask(__name__)

config: dict = None
lastAuthTime: int = 0

with open('./config.yml', 'r', encoding='utf-8') as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)
print(config)

def get_initialization_vector(secret_key):
    iv = bytearray(16) 
    encoded_key = secret_key.encode() 
    iv[:len(encoded_key)] = encoded_key[:16]
    return bytes(iv)

def encrypt(plaintext, secret_key):
    iv = get_initialization_vector(secret_key)
    cipher = AES.new(secret_key.encode(), AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def decrypt(ciphertext, secret_key):
    iv = get_initialization_vector(secret_key)
    cipher = AES.new(secret_key.encode(), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode()
    
def getAccount() -> dict:
    acc :list = str(random.choice(config['accounts'])).split('-')
    username = acc[0]
    password = acc[1]
    hwid = acc[2]
    return {'username': username, 'password': password, 'hwid': hwid}

def doAuth(account: dict) -> dict:
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
    lastAuthTime = time.time()
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
    sending_secret = request.headers['X-Gateway-Secret']
    try:
        if not decrypt(config['gateway']['secret_key'], sending_secret) == 'Hello World':
            return 'Gateway Secret is not correct.', 403
    except Exception:
        return 'Gateway Secret is not correct.', 403
    if not lastAuthTime+config['gateway']['colddown']>time.time():
        return {'token': 'null', 'status': 'NO_ACCOUNT', 'colddown': {'time': lastAuthTime+config['gateway']['colddown']}}, 200
    return doAuth(getAccount()), 200

@app.route("/gateway/heartbeat")
def heartbeat():
    sending_secret = request.headers['X-Gateway-Secret']
    try:
        if not decrypt(config['gateway']['secret_key'], sending_secret) == 'Hello World':
            return 'Gateway Secret is not correct.', 403
    except Exception:
        return 'Gateway Secret is not correct.', 403
    return {'time': time.time(), 'colddown': {'time': lastAuthTime-config['gateway']['colddown']}, 'implementation': 'zszfympx/DingZhenRefreshTokenPY'}, 200

if __name__ == '__main__':
    app.run(config['flask']['host'], config['flask']['port'], config['flask']['debug'])     
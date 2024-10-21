from flask import Flask, request
from crypto.Cipher import AES
from crypto.Util.Padding import unpad, pad
import requests
import base64
import yaml
import random
import time

app = Flask(__name__)

config: dict = None

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
    try:
        response = requests.post(url, headers=headers, data=data)

        if response.text:
            response_string = response.text.strip()

            if response.ok:
                if len(response_string) != 33:
                    res = None

                    if response_string == "1006":
                        res = "共享账户无法进行登录,是IP被封禁了吗"
                        
                        
                    elif response_string == "102":
                        res = "共享账户账户似乎被封禁了"
                        
                    else:
                        res = "共享账户在验证的时候产生了未知错误"
                        
                    return res

            return response.text
        else:
            return "服务器发生未知错误"

    except Exception:
        return "服务器发生未知错误"        

@app.route("/")
def pong():
    return "DingZhenRefreshPY(https://github.com/zszfympx/DingZhenRefreshPY)"

@app.route("/gateway/token")
def refresh_token():
    sending_secret = request.headers['X-Gateway-Secret']
    if not decrypt(config['gateway']['secret_key'], sending_secret) == 'Hello World':
        return 'Gateway Secret is not correct.', 403
    token = doAuth(getAccount())
    if token!=33:
        return token, 500
    else:
        return token, 200

@app.route("/gateway/heartbeat")
def heartbeat():
    sending_secret = request.headers['X-Gateway-Secret']
    if not decrypt(config['gateway']['secret_key'], sending_secret) == 'Hello World':
        return 'Gateway Secret is not correct.', 403
    return {'time': time.time(), 'colddown': {'time': time.time()-3600}, 'implementation': 'zszfympx/DingZhenRefreshTokenPY'}, 200

if __name__ == '__main__':
    with open('config.yml', 'r') as f:
        config = yaml.load(f)
    app.run(config['flask']['host'], config['flask']['port'], config['flask']['debug'])
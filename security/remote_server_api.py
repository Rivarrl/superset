"""
this file should be the api of your remote server
for example, your login service from your company
e.g. provide email and password, send this information to your remote server
waiting for the response from remote server. If remote server authorized this email and password
then it will be ok to login this user.
"""
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import requests
import logging

logger = logging.getLogger(__name__)


def authenticate(email, psw):
    """

    :param email:
    :param psw:
    :return:
    """
    public_key = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANL378k3RiZHWx5AfJqdH9xRNBmD9wGD2iRe41HdTNF8RUhNnHit5NpMNtGL0NPTSSpPjjI1kJfVorRvaQerUgkCAwEAAQ=='
    cipher_public = PKCS1_v1_5.new(RSA.importKey(base64.b64decode(public_key)))
    encrypt_psw = base64.b64encode(cipher_public.encrypt(psw.encode())).decode()
    server_url = "http://fawivi-sit-k8-operatingweb.faw.cn"
    auth_url = f'{server_url}/rbac/auth/login'
    post_data = {
        "platId": "303191694492971008",
        "userAccount": email.split('@')[0],
        "userPassword": encrypt_psw
    }
    headers = {}
    # this is an example of real world case
    response = requests.post(auth_url, json=post_data, headers=headers, verify=False)
    if response.status_code != 200:
        logger.warn("failed to auth user: %s, status: %s, response: %s " %
                    (email, response.status_code, response.text))
        return None
    response_json = response.json()
    if response_json['statusCode'] != '0':
        print(response_json)
        logger.warn(f'post api data failed. url: {auth_url}.')
        return None

    userinfo = dict(email=email)
    return userinfo

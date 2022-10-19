import time
import hmac
import hashlib
import requests

# you should provide appId, appSecret and address
appId = '000000000000000000000000000000000000000000000000000000000000000001'
appSecret = '000000000000000000000000000000000000000000000000000000000000000002'
timeStamp = str(int(time.time() * 1000))

method = 'POST'
host = 'https://avengerdao.org'
url = '/api/v1/address-security'
body = '{"address":"0x0000000000000000000000000000000000000003"}'

data = ';'.join([appId, timeStamp, 'nonce', method, url, body])

hashInHex = hmac.new(bytes(appSecret , 'utf-8'), msg = bytes(data , 'utf-8'), digestmod = hashlib.sha256).hexdigest()
headers = {
	'Content-Type': 'application/json',
	'X-Signature-signature': hashInHex,
	'X-Signature-appid': appId,
	'X-Signature-timestamp': timeStamp,
	'X-Signature-nonce': 'nonce'
}

x = requests.post(host + url, data = body, headers = headers)
print(x.text)

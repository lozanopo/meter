import hmac
import hashlib

# Incoming information from post request
body = '{\"address\":\"0x0000000000000000000000000000000000000003\"}'  # Incoming request body
incomingSignature = '6d668a3a07ed9b36418c80911184d8981dbf815085f1eb97a1e536282db0b1e2'  # 'X-Signature-signature' header
appId = '000000000000000000000000000000000000000000000000000000000000000001'  # 'X-Signature-appid' header
timeStamp = '1666255054045'  # 'X-Signature-timestamp' header
nonce = 'nonce'  # 'X-Signature-nonce' header
path = '/api/v1/address-security'  # Provider path
method = 'POST'  # Provider rest API method
data = ';'.join([appId, timeStamp, 'nonce', method, path, body])

# Query appSecret using appId
appSecret = '000000000000000000000000000000000000000000000000000000000000000002'

generatedSignature = hmac.new(bytes(appSecret, 'utf-8'), msg=bytes(data, 'utf-8'), digestmod=hashlib.sha256).hexdigest()

isValidSignature = incomingSignature == generatedSignature

print(isValidSignature)
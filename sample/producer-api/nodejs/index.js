const HmacSHA256 = require('crypto-js/hmac-sha256')
const EncodeHex = require('crypto-js/enc-hex')

// Incoming information from post request
const body = JSON.stringify({ address: '0x0000000000000000000000000000000000000003' }) // Incoming request body
const incomingSignature = '6d668a3a07ed9b36418c80911184d8981dbf815085f1eb97a1e536282db0b1e2' // 'X-Signature-signature' header
const appId = '000000000000000000000000000000000000000000000000000000000000000001' //'X-Signature-appid' header
const timeStamp = '1666255054045' // 'X-Signature-timestamp' header
const nonce = 'nonce' // 'X-Signature-nonce' header
const path = '/api/v1/address-security' // Provider path
const method = 'POST' // Provider rest API method
const data = [appId, timeStamp, nonce, method, path, body].join(';')

// Query appSecret using appId
const appSecret = '000000000000000000000000000000000000000000000000000000000000000002'

const hash = HmacSHA256(data, appSecret)
const generatedSignature = EncodeHex.stringify(hash)

isValidSignature = Boolean(incomingSignature === generatedSignature)


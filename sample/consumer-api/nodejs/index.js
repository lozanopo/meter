const axios = require('axios')
const HmacSHA256 = require('crypto-js/hmac-sha256')
const EncodeHex = require('crypto-js/enc-hex')

// you should provide appId, appSecret and address
const appId = '000000000000000000000000000000000000000000000000000000000000000001'
const appSecret = '000000000000000000000000000000000000000000000000000000000000000002'
const body = JSON.stringify({ address: '0x0000000000000000000000000000000000000003' })

const timeStamp = new Date().valueOf().toString()
const method = 'POST'
const host = 'https://avengerdao.org'
const url = '/api/v1/address-security'

const data = [appId, timeStamp, 'nonce', method, url, body].join(';')
const hash = HmacSHA256(data, appSecret)
const hashInHex = EncodeHex.stringify(hash)

axios.post(host + url, body, {
	headers: {
		"Content-Type": "application/json",
		"X-Signature-signature": hashInHex,
		"X-Signature-appid": appId,
		"X-Signature-timestamp": timeStamp,
		"X-Signature-nonce": "nonce",
	}
}).then(res => console.log(JSON.stringify(res.data)))
.catch(err => console.error(err))

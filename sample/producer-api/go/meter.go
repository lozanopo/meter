package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func main() {
	//Incoming information from post request
	postBody, _ := json.Marshal(map[string]string{
		"address": "0x0000000000000000000000000000000000000003", // the address for checking its trust score
	})
	body := string(postBody)                                                                // Incoming request body
	incomingSignature := "6d668a3a07ed9b36418c80911184d8981dbf815085f1eb97a1e536282db0b1e2" // 'X-Signature-signature' header
	appid := "000000000000000000000000000000000000000000000000000000000000000001"           // 'X-Signature-appid' header
	timestamp := "1666255054045"                                                            // 'X-Signature-timestamp' header
	nonce := "nonce"                                                                        // 'X-Signature-nonce' header
	method := "POST"                                                                        // Provider rest API method
	path := "/api/v1/address-security"                                                      // Provider path
	query := ""                                                                             // The query string, it can be empty

	// Query appSecret using appId
	appSecret := "000000000000000000000000000000000000000000000000000000000000000002"

	msgForSig := GenerateMsgForSig(appid, timestamp, nonce, method, path, query, body)
	generatedSignature := ComputeSig(msgForSig, appSecret)

	isValidSignature := incomingSignature == generatedSignature
	fmt.Println("is valid: ", isValidSignature)
}

func GenerateMsgForSig(appid, timestamp, nonce, method, path, query, body string) string {
	var msgForSig []byte

	if query != "" {
		msgForSig = []byte(fmt.Sprintf("%s;%s;%s;%s;%s;%s;%s", appid, timestamp, nonce, method, path, query, body))
	} else {
		msgForSig = []byte(fmt.Sprintf("%s;%s;%s;%s;%s;%s", appid, timestamp, nonce, method, path, body))
	}

	fmt.Println("msgForSig: ", string(msgForSig))

	return string(msgForSig)
}

func ComputeSig(msgForSig, appSecret string) string {
	message := []byte(msgForSig)

	key := []byte(appSecret)
	h := hmac.New(sha256.New, key)
	h.Write(message)

	return hex.EncodeToString(h.Sum(nil))
}

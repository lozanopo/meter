package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

var avengerdaoURL = "https://avengerdao.org" // the main url of the avengerdao site
var publicAccess = true                      // true for public access, false for access with app id

func main() {
	// request body
	postBody, _ := json.Marshal(map[string]string{
		"address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // the address for checking its trust score
	})

	reqBody := bytes.NewBuffer(postBody)

	// signature
	appSecret := "" // the app secret

	appid := ""                                           // the app id
	timestamp := strconv.FormatInt(time.Now().Unix(), 10) // the timestamp
	nonce := strconv.Itoa(rand.Intn(9999999))             // the nonce
	method := "POST"                                      // the http method
	url := "/api/v1/address-security"                     // the url
	query := ""                                           // the query string, it can be empty
	body := string(postBody)                              // the request body

	msgForSig := GenerateMsgForSig(appid, timestamp, nonce, method, url, query, body)
	sig := ComputeSig(msgForSig, appSecret)

	req, err := http.NewRequest(method, avengerdaoURL+url, reqBody)
	if err != nil {
		panic(err)
	}

	if !publicAccess {
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
		req.Header.Set("X-Signature-appid", appid)
		req.Header.Set("X-Signature-timestamp", timestamp)
		req.Header.Set("X-Signature-nonce", nonce)
		req.Header.Set("X-Signature-signature", sig)
	}

	fmt.Println("signature: ", sig)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	fmt.Println("response status:", resp.Status)

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)

		if err != nil {
			panic(err)
		}

		bodyString := string(bodyBytes)
		fmt.Println(bodyString)
	}
}

func GenerateMsgForSig(appid, timestamp, nonce, method, url, query, body string) string {
	var msgForSig []byte

	if query != "" {
		msgForSig = []byte(fmt.Sprintf("%s;%s;%s;%s;%s;%s;%s", appid, timestamp, nonce, method, url, query, body))
	} else {
		msgForSig = []byte(fmt.Sprintf("%s;%s;%s;%s;%s;%s", appid, timestamp, nonce, method, url, body))
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

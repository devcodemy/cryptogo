package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

const NONCE_SIZE = 4

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func createGCM(passphrase string) (cipher.AEAD, error) {
	key := []byte(createHash(passphrase))
	block, _ := aes.NewCipher(key)
	return cipher.NewGCMWithNonceSize(block, NONCE_SIZE) // length 64
}

func encrypt(data []byte, passphrase string) []byte {
	gcm, _ := createGCM(passphrase)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil)
}

func decrypt(data []byte, passphrase string) []byte {
	gcm, _ := createGCM(passphrase)
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open(nil, nonce, cipherText, nil)
	return plaintext
}

func main() {
	passphrase := "asdfgh"
	resultEncrypted := encrypt([]byte("Hello World!"), passphrase)
	log.Println(hex.EncodeToString(resultEncrypted))

	someEcrypted := "72c1744210164166495701505c892f2d62691b4a8ccd97e000bd73d56d210dcd"

	toDecodeString, _ := hex.DecodeString(someEcrypted)
	resultDecrypted := decrypt(toDecodeString, passphrase)
	log.Println(string(resultDecrypted))
}

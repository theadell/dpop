package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func generateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

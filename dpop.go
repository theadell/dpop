package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type dpopHeader struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	Jwk json.RawMessage `json:"jwk"`
}

type dpopPayload struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
}

func generateECDSAKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func base64URLEncode(src []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
}

func createDPoPProof(privateKey *ecdsa.PrivateKey, httpMethod, httpURL string) (string, error) {
	// Create DPoP Header
	publicKey := &privateKey.PublicKey

	// Ensure the coordinates are zero-padded to the correct length
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	curveOrderBytes := (publicKey.Curve.Params().BitSize + 7) / 8
	paddedX := append(bytes.Repeat([]byte{0}, curveOrderBytes-len(xBytes)), xBytes...)
	paddedY := append(bytes.Repeat([]byte{0}, curveOrderBytes-len(yBytes)), yBytes...)

	// Encode x and y coordinates
	x := base64URLEncode(paddedX)
	y := base64URLEncode(paddedY)
	jwk, _ := json.Marshal(map[string]any{
		"kty": "EC",
		"x":   x,
		"y":   y,
		"crv": "P-256",
	})
	header := dpopHeader{
		Typ: "dpop+jwt",
		Alg: "ES256",
		Jwk: jwk,
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64URLEncode(headerBytes)

	// Create DPoP Payload
	payload := dpopPayload{
		Jti: generateJTI(), // This should be generated uniquely
		Htm: httpMethod,
		Htu: httpURL,
		Iat: time.Now().Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64URLEncode(payloadBytes)

	// Create Signature
	unsignedToken := headerB64 + "." + payloadB64
	h := sha256.New()
	h.Write([]byte(unsignedToken))
	hash := h.Sum(nil)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash)
	signature := append(r.Bytes(), s.Bytes()...)
	signatureB64 := base64URLEncode(signature)

	// Final DPoP Proof
	dpopProof := unsignedToken + "." + signatureB64
	return dpopProof, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *Config) RetrieveToken(ctx context.Context, code string) (*TokenResponse, error) {
	if c.DPoPPrivateKey == nil {
		return nil, fmt.Errorf("DPoP private key is not set in config")
	}

	dpopProof, err := createDPoPProof(c.DPoPPrivateKey, "POST", c.Endpoint.TokenURL)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("client_id", c.ClientID)
	form.Add("client_secret", c.ClientSecret)
	form.Add("code", code)
	form.Add("redirect_uri", c.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("DPoP", dpopProof)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve token: %s", resp.Status)
	}

	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return &tokenResp, nil
}

func generateJTI() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

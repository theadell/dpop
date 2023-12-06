package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	privateKey, err := generateECDSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	config := Config{
		ClientID:     "dpop",
		ClientSecret: "78uDJ7h3wqy5IxEirVmcXHDMdKxa4ZWO",
		Endpoint: Endpoint{
			AuthURL:  "http://localhost:8080/realms/dev/protocol/openid-connect/auth",
			TokenURL: "http://localhost:8080/realms/dev/protocol/openid-connect/token",
		},
		RedirectURL:    "http://localhost:8081/callback",
		DPoPPrivateKey: privateKey,
	}

	// Home Page Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><h1>Welcome</h1><a href="/authorize">Authorize</a></body></html>`)
	})

	// Mock Authorization Endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		authUrl := config.AuthCodeURL("198230293029308594830293092458309840343")
		http.Redirect(w, r, authUrl, http.StatusFound)
	})

	// Callback Handler
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}

		tokenResponse, err := config.RetrieveToken(context.Background(), code)
		if err != nil {
			http.Error(w, "Failed to retrieve token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Display the token response
		responseBytes, _ := json.MarshalIndent(tokenResponse, "", "  ")

		introspectionResponseWithDPoP, err := introspectToken(&config, tokenResponse.AccessToken, true)
		if err != nil {
			introspectionResponseWithDPoP = "Error introspecting token with DPoP: " + err.Error()
		}

		// Introspect token without DPoP
		introspectionResponseWithoutDPoP, err := introspectToken(&config, tokenResponse.AccessToken, false)
		if err != nil {
			introspectionResponseWithoutDPoP = "Error introspecting token without DPoP: " + err.Error()
		}

		// Display the responses
		fmt.Fprintf(w, `<html><body>
        <h1>Token Response</h1>
        <pre>%s</pre>
        <h2>Introspection with DPoP</h2>
        <pre>%s</pre>
        <h2>Introspection without DPoP</h2>
        <pre>%s</pre>
        </body></html>`,
			string(responseBytes),
			introspectionResponseWithDPoP,
			introspectionResponseWithoutDPoP)
	})

	log.Println("Server started at http://localhost:8081")
	log.Fatal(http.ListenAndServe("localhost:8081", nil))
}

func introspectToken(config *Config, token string, includeDPoP bool) (string, error) {
	// Prepare the introspection request data
	data := url.Values{}
	data.Set("token", token)

	// Create the request
	req, err := http.NewRequest("POST", "http://localhost:8080/realms/dev/protocol/openid-connect/token/introspect", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	// Include DPoP proof if required
	if includeDPoP {
		dpopProof, err := createDPoPProof(config.DPoPPrivateKey, "POST", req.URL.String())
		if err != nil {
			return "", err
		}
		req.Header.Set("DPoP", dpopProof)
	}

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read and return the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

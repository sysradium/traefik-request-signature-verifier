package traefik_request_signature_verifier

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type Config struct {
	ResponseMessage     string   `json:"responseMessage,omitempty"`
	SecretKey           string   `json:"secretKey,omitempty"`
	SignatureHeader     string   `json:"signatureHeader,omitempty"`
	DateHeader          string   `json:"dateHeader,omitempty"`
	AuthorizationHeader string   `json:"authorizationHeader,omitempty"`
	AppIDHeader         string   `json:"appIDHeader,omitempty"`
	Headers             []string `json:"headers,omitempty"`
	ResponseCode        int      `json:"responseCode,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
	KeyStoreURL         string   `json:"keyStoreURL,omitempty"`
}

func CreateConfig() *Config {
	config := &Config{}
	return config
}

func (c *Config) SetDefaults() {
	if c.Headers == nil {
		c.Headers = []string{"Authorization", "APP-ID"}
	}
	if c.ResponseCode == 0 {
		c.ResponseCode = http.StatusForbidden
	}
	if c.ResponseMessage == "" {
		c.ResponseMessage = "{\"error\": \"invalid checksum\"}"
	}
	if c.SecretKey == "" {
		c.SecretKey = "62df864b-dd00-43e3-ac0a-5760ae26d3f5"
	}
	if c.DateHeader == "" {
		c.DateHeader = "X-Date"
	}
	if c.SignatureHeader == "" {
		c.SignatureHeader = "X-Request-Signature"
	}
}

type KeyStore interface {
	Current() string
	Rotate(ctx context.Context) (string, error)
	Set(ctx context.Context, key string) error
}

type signatureVerifier struct {
	next     http.Handler
	verifier *RequestVerifier
	cfg      *Config
	name     string
	keyStore KeyStore
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var keyStore KeyStore
	config.SetDefaults()
	jd, _ := json.MarshalIndent(config, "", "\t")
	log.Printf("received configuration: %s", jd)
	if config.KeyStoreURL != "" {
		ks := &LocalHTTP{URL: config.KeyStoreURL}
		if err := initSecretKey(ks); err != nil {
			log.Printf("Failed to initialize key store: %+v", err)
		}
		keyStore = ks
	} else {
		keyStore = &Static{key: config.SecretKey}
	}

	return &signatureVerifier{
		name:     name,
		next:     next,
		cfg:      config,
		keyStore: keyStore,
		verifier: &RequestVerifier{
			headers:    config.Headers,
			dateHeader: config.DateHeader,
			sigHeader:  config.SignatureHeader,
		},
	}, nil
}

func (r *signatureVerifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	requestValid := true
	// Trying to verify the request with the current key
	if err := r.verifier.VerifyRequest(req, r.keyStore.Current()); errors.Is(err, ErrInvalidSignature) {
		log.Printf("signature verification failed with current key: %v", err)
		// Trying to retrieve and update the key
		if err := r.RetrieveAndUpdateKey(req); err != nil {
			log.Printf("signature invalid after update: %v", err)
			requestValid = false
		}
	} else if err != nil {
		log.Printf("error validating request: %+v", err)
		requestValid = false
	}
	if !requestValid && !r.cfg.DryRun {
		http.Error(w, r.cfg.ResponseMessage, r.cfg.ResponseCode)
		return
	}
	r.next.ServeHTTP(w, req)
}

func initSecretKey(keyStore KeyStore) error {
	ctx := context.Background()
	if err := keyStore.Set(ctx, ""); err != nil {
		if !errors.Is(err, ErrNoValidKeysFound) {
			return err
		}
	}
	return nil
}

func (r *signatureVerifier) RetrieveAndUpdateKey(req *http.Request) error {
	ctx := context.Background()
	newKey, err := r.keyStore.Rotate(ctx)
	if err != nil {
		log.Printf("Error rotating to new key: %v", err)
		return ErrNoValidKeysFound
	} else if !r.verifier.ValidateSignature(req, newKey) {
		return ErrInvalidSignature
	}
	return nil
}

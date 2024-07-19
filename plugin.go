package traefik_request_signature_verifier

import (
	"context"
	"errors"
	"log"
	"net/http"
)

type Config struct {
	ResponseMessage string
	SecretKey       string
	SignatureHeader string
	DateHeader      string
	Headers         []string
	ResponseCode    int
	DryRun          bool
}

func CreateConfig() *Config {
	return &Config{
		Headers:         make([]string, 0),
		ResponseCode:    http.StatusForbidden,
		ResponseMessage: "{\"error\": \"invalid checksum\"}",
		SecretKey:       "62df864b-dd00-43e3-ac0a-5760ae26d3f5",
		SignatureHeader: "X-Request-Signature",
		DateHeader:      "X-Date",
	}
}

type signatureVerifier struct {
	next     http.Handler
	verifier *RequestVerifier
	cfg      *Config
	name     string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &signatureVerifier{
		name: name,
		next: next,
		cfg:  config,
		verifier: &RequestVerifier{
			headers:    config.Headers,
			sigHeader:  config.SignatureHeader,
			dateHeader: config.DateHeader,
			secretKey: func() string {
				return config.SecretKey
			},
		},
	}, nil
}

func (r *signatureVerifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := r.verifier.VerifyRequest(req); err != nil {
		if !errors.Is(err, ErrSignatureNotPresent) {
			log.Printf("signature verification failed: %v", err)
		}

		if !r.cfg.DryRun {
			http.Error(w, r.cfg.ResponseMessage, r.cfg.ResponseCode)
			return
		}
	}

	r.next.ServeHTTP(w, req)
}

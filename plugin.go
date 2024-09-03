package traefik_request_signature_verifier

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ResponseMessage     string
	SecretKey           string
	SignatureHeader     string
	DateHeader          string
	AuthorizationHeader string
	AppIDHeader         string
	Headers             []string
	ResponseCode        int
	DryRun              bool
	RedisURI            string `envconfig:"REDIS_URI" required:"true"`
}

func CreateConfig() *Config {
	config := &Config{
		Headers:         []string{"Authorization", "APP-ID"},
		ResponseCode:    http.StatusForbidden,
		ResponseMessage: "{\"error\": \"invalid checksum\"}",
		SecretKey:       "62df864b-dd00-43e3-ac0a-5760ae26d3f5",
		DateHeader:      "X-Date",
		SignatureHeader: "X-Request-Signature",
	}
	if err := envconfig.Process("", config); err != nil {
		log.Fatalf("Failed to process env config: %v", err)
	}

	return config
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

	if config.RedisURI != "" {
		opts, err := redis.ParseURL(config.RedisURI)
		if err != nil {
			return nil, err
		}
		redisClient := redis.NewClient(opts)
		redisKeyStore := &Redis{client: redisClient}

		if err := initSecretKey(redisKeyStore); err != nil {
			log.Printf("Failed to initialize Redis key store: %v", err)
		}
		keyStore = redisKeyStore
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

func initSecretKey(keyStore *Redis) error {
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
	if err == nil {
		if r.verifier.ValidateSignature(req, newKey) {
			return nil
		}
	} else {
		log.Printf("Error rotating to new key: %v", err)
		return ErrNoValidKeysFound
	}
	return ErrInvalidSignature
}

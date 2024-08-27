package traefik_request_signature_verifier

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ResponseMessage string
	SecretKey       string
	SignatureHeader string
	DateHeader      string
	Headers         []string
	ResponseCode    int
	DryRun          bool
	RedisURI        string `envconfig:"REDIS_URI" required:"true"`
}

func CreateConfig() *Config {
	config := &Config{
		Headers:         make([]string, 0),
		ResponseCode:    http.StatusForbidden,
		ResponseMessage: "{\"error\": \"invalid checksum\"}",
		SecretKey:       "62df864b-dd00-43e3-ac0a-5760ae26d3f5",
		DateHeader:      "X-Date",
	}
	if err := envconfig.Process("", config); err != nil {
		log.Fatalf("Failed to process env config: %v", err)
	}

	return config
}

type signatureVerifier struct {
	next        http.Handler
	verifier    *RequestVerifier
	cfg         *Config
	name        string
	redisClient *redis.Client
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Инициализация клиента Redis
	opts, err := redis.ParseURL(config.RedisURI)
	if err != nil {
		return nil, err
	}
	redisClient := redis.NewClient(opts)
	config.initSecretKey(redisClient)
	return &signatureVerifier{
		name:        name,
		next:        next,
		cfg:         config,
		redisClient: redisClient,
		verifier: &RequestVerifier{
			headers:    config.Headers,
			dateHeader: config.DateHeader,
			secretKey: func() string {
				return config.SecretKey
			},
		},
	}, nil
}

func (r *signatureVerifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Сначала пытаемся верифицировать запрос с использованием текущего ключа.
	if err := r.verifier.VerifyRequest(req); err != nil {
		if !errors.Is(err, ErrSignatureNotPresent) {
			log.Printf("signature verification failed with current key: %v", err)
		}

		// Если верификация неудачна, пытаемся обновить ключ и повторить проверку.
		if err := r.RetrieveAndUpdateKey(req); err != nil {
			log.Printf("Error retrieving or updating key: %v", err)
			http.Error(w, "Internal server error", http.StatusUnauthorized)
			return
		}

	}
	r.next.ServeHTTP(w, req)
}

func (cfg *Config) initSecretKey(redisClient *redis.Client) {
	// Проверка, что URI для Redis предоставлен
	if cfg.RedisURI == "" {
		log.Println("REDIS_URI environment variable not set or empty")
	}
	ctx := context.Background()
	key, err := redisClient.Get(ctx, "query-signature-key").Result()
	if err != nil || key == "" {
		log.Printf("Failed to retrieve initial key from Redis or key is empty: %v, using default key.", err)
	} else {
		cfg.SecretKey = key
	}
}

func (r *signatureVerifier) RetrieveAndUpdateKey(req *http.Request) error {
	ctx := context.Background()

	// Попытка использования нового ключа из Redis
	newKey, err := r.redisClient.Get(ctx, "query-signature-key").Result()
	if err == nil {
		if r.verifier.ValidateSignature(req, newKey) {
			r.verifier.UpdateKey(newKey)
			return nil
		}
	} else {
		log.Printf("Error retrieving new key from Redis: %v", err)
	}

	// Если новый ключ не прошел проверку, попробуем старый ключ
	oldKey, err := r.redisClient.Get(ctx, "query-signature-key-old").Result()
	if err == nil {
		if r.verifier.ValidateSignature(req, oldKey) {
			return nil
		}
	} else {
		log.Printf("Error retrieving old key from Redis: %v", err)
	}

	return fmt.Errorf("no valid keys found")
}

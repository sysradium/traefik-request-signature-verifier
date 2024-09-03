package traefik_request_signature_verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	ErrSignatureExpired    = errors.New("signature has expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrSignatureNotPresent = errors.New("signature not present")
	ErrNoValidKeysFound    = errors.New("no valid keys found")
)

type InvalidDateFormatError string

func (idfe InvalidDateFormatError) Error() string {
	return fmt.Sprintf("invalid date format: %s", string(idfe))
}

type RequestVerifier struct {
	sigHeader  string
	dateHeader string
	headers    []string
}

func (v *RequestVerifier) Checksum(r *http.Request, key string) string {
	var (
		data []byte
		err  error
	)

	switch r.Method {
	case "GET", "HEAD", "DELETE":
		data = []byte(r.URL.RawQuery)
	case "POST", "PUT":
		r.Body, data, err = drainBody(r.Body)
		if err != nil {
			return "-"
		}
	}
	hash := sha256.New()
	hash.Write([]byte(key))

	for _, h := range v.headers {
		hash.Write([]byte(getNormalizedHeader(r, h)))
	}
	hash.Write(data)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (v *RequestVerifier) VerifyRequest(r *http.Request, key string) error {
	sig := r.Header.Get(v.sigHeader)
	if sig == "" {
		return ErrSignatureNotPresent
	}
	if v.dateHeader != "" {
		dateStr := r.Header.Get(v.dateHeader)
		date, err := time.Parse(time.RFC1123, dateStr)
		if err != nil {
			return errors.Join(err, InvalidDateFormatError(fmt.Sprintf("error parsing %q: %+v", dateStr, err)))
		}
		if !date.Round(time.Minute).Equal(time.Now().Round(time.Minute)) {
			return ErrSignatureExpired
		}
	}
	if strings.ToLower(sig) != v.Checksum(r, key) {
		return ErrInvalidSignature
	}
	return nil
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (res io.ReadCloser, data []byte, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, nil, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return io.NopCloser(&buf), nil, err
	}
	if err = b.Close(); err != nil {
		return io.NopCloser(&buf), nil, err
	}
	return io.NopCloser(&buf), buf.Bytes(), nil
}

// Helper function to validate the request signature with the given key
func (v *RequestVerifier) ValidateSignature(r *http.Request, key string) bool {
	sig := r.Header.Get(v.sigHeader)
	if sig == "" {
		return false
	}
	computedSignature := v.Checksum(r, key)
	return strings.ToLower(sig) == computedSignature
}

type Static struct{ key string }

func (s *Static) Current() string {
	return s.key
}

func (s *Static) Rotate(ctx context.Context) (string, error) {
	return s.key, nil
}

func (s *Static) Set(ctx context.Context, key string) error {
	s.key = key
	return nil
}

type Redis struct {
	client     *redis.Client
	currentKey string
}

func (r *Redis) Current() string {
	return r.currentKey
}

func (r *Redis) Rotate(ctx context.Context) (string, error) {
	newKey, err := r.client.Get(ctx, "query-signature-key").Result()
	if err == nil && newKey != r.currentKey {
		r.currentKey = newKey // update the current key to the new key
		return newKey, nil
	}
	oldKey, err := r.client.Get(ctx, "query-signature-key-old").Result()
	if err == nil && oldKey != r.currentKey {
		return oldKey, nil
	}
	return "", ErrNoValidKeysFound
}

func (r *Redis) Set(ctx context.Context, key string) error {
	if newKey, err := r.client.Get(ctx, "query-signature-key").Result(); err == nil {
		r.currentKey = newKey
		return nil
	}
	if oldKey, err := r.client.Get(ctx, "query-signature-key-old").Result(); err == nil {
		r.currentKey = oldKey
		return nil
	}
	return ErrNoValidKeysFound
}

func getNormalizedHeader(r *http.Request, header string) string {
	switch strings.ToLower(header) {
	case "authorization", "xauthorization", "x-authorization":
		return r.Header.Get("x-authorization")
	case "app-id":
		return r.Header.Get("x-app-id")
	default:
		return r.Header.Get(header)
	}
}

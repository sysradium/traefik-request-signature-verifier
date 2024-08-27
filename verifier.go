package traefik_request_signature_verifier

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrSignatureExpired    = errors.New("signature has expired")
	ErrDateInvalidFormat   = errors.New("invalid date format")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrSignatureNotPresent = errors.New("signature not present")
)

type RequestVerifier struct {
	secretKey  func() string
	dateHeader string
	headers    []string
}

func (v *RequestVerifier) Checksum(r *http.Request, key ...string) string {
	// Используем переданный ключ, если он есть, иначе используем текущий ключ
	var actualKey string
	if len(key) > 0 {
		actualKey = key[0]
	} else {
		actualKey = v.secretKey()
	}
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
	hash.Write([]byte(actualKey))

	for _, h := range v.headers {
		hash.Write([]byte(r.Header.Get(h)))
	}

	hash.Write(data)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (v *RequestVerifier) VerifyRequest(r *http.Request) error {
	sig, found := getSignatureHeader(r)
	if !found {
		return ErrSignatureNotPresent
	}

	if v.dateHeader != "" {
		dateStr := r.Header.Get(v.dateHeader)
		date, err := time.Parse(time.RFC1123, dateStr)
		if err != nil {
			return errors.Join(err, ErrDateInvalidFormat)
		}

		if !date.Round(time.Minute).Equal(time.Now().Round(time.Minute)) {
			return ErrSignatureExpired
		}
	}

	if strings.ToLower(sig) != v.Checksum(r) {
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
func (v *RequestVerifier) ValidateSignature(r *http.Request, key ...string) bool {
	sig, found := getSignatureHeader(r)
	if !found {
		return false
	}
	computedSignature := v.Checksum(r, key...)
	return strings.ToLower(sig) == computedSignature
}

func (v *RequestVerifier) UpdateKey(newKey string) {
	v.secretKey = func() string {
		return newKey
	}
}

func getSignatureHeader(r *http.Request) (string, bool) {
	sig := r.Header.Get("X-Request-Signature")
	if sig != "" {
		return sig, true
	}
	sig = r.Header.Get("x-request-signature")
	if sig != "" {
		return sig, true
	}

	return "", false
}

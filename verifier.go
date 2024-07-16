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
	ErrInvalidDate         = errors.New("invalid date")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrSignatureNotPresent = errors.New("signature not present")
)

type RequestVerifier struct {
	secretKey  func() string
	sigHeader  string
	dateHeader string
	headers    []string
}

func (v *RequestVerifier) Checksum(r *http.Request) string {
	var binData []byte
	var err error
	switch r.Method {
	case "GET", "HEAD", "DELETE":
		binData = []byte(r.URL.RawQuery)
	case "POST", "PUT":
		r.Body, binData, err = drainBody(r.Body)
		if err != nil {
			return "-"
		}
	}
	hash := sha256.New()
	hash.Write([]byte(v.secretKey()))

	for _, h := range v.headers {
		hash.Write([]byte(r.Header.Get(h)))
	}

	hash.Write(binData)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (v *RequestVerifier) VerifyRequest(r *http.Request) error {
	sig := r.Header.Get(v.sigHeader)
	if sig == "" {
		return ErrSignatureNotPresent
	}

	if v.dateHeader != "" {
		dateStr := r.Header.Get(v.dateHeader)
		date, err := time.Parse(time.RFC1123, dateStr)
		if err != nil {
			return errors.Join(err, ErrInvalidDate)
		}

		if !date.Round(time.Minute).Equal(time.Now().Round(time.Minute)) {
			return ErrInvalidDate
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

package hmacauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type middleware func(http.ResponseWriter, *http.Request)
type keyLocator func(string) string

type Options struct {
	SignedHeaders       []string
	SecretKey           keyLocator
	SignatureExpiration int32
}

type AuthBits struct {
	APIKey          string
	Signature       string
	TimestampString string
	Timestamp       time.Time
}

func (ab AuthBits) IsValid() bool {
	return ab.APIKey != "" &&
		ab.Signature != "" &&
		ab.TimestampString != "" &&
		!ab.Timestamp.IsZero()
}

func HMACAuth(options Options) middleware {
	// Validate options
	if options.SecretKey == nil {
		panic("HMACAuth Secret Key Locator Required")
	}

	return func(res http.ResponseWriter, req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(res, "Authorization Header Not Supplied", 401)
			return
		}

		authBits, err := parseAuthHeader(authHeader)
		if err != nil {
			http.Error(res, err.Error(), 401)
			return
		}

		if timeoutErr := validateTimestamp(authBits.Timestamp, &options); timeoutErr != nil {
			http.Error(res, err.Error(), 401)
			return
		}

		str, err := stringToSign(req, &options, authBits.TimestampString)
		if err != nil {
			http.Error(res, err.Error(), 401)
			return
		}

		secretKey := options.SecretKey(authBits.APIKey)
		if secretKey == "" {
			http.Error(res, "Invalid APIKey", 401)
			return
		}

		sig := signString(str, secretKey)
		if sig != authBits.Signature {
			http.Error(res, "Invalid Signature", 401)
			return
		}
	}
}

func signString(str string, secret string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func stringToSign(req *http.Request, options *Options, timestamp string) (string, error) {
	var buffer bytes.Buffer

	// Standard
	buffer.WriteString(req.Method)
	buffer.WriteString("\n")
	buffer.WriteString(req.Host)
	buffer.WriteString("\n")
	buffer.WriteString(req.URL.RequestURI())
	buffer.WriteString("\n")
	buffer.WriteString(timestamp)
	buffer.WriteString("\n")

	// Headers
	sort.Strings(options.SignedHeaders)
	for _, header := range options.SignedHeaders {
		val := req.Header.Get(header)
		if val == "" {
			return "",
				errors.New("Invalid Request. Missing Required Header: " + header)
		}
		buffer.WriteString(val)
		buffer.WriteString("\n")
	}

	return buffer.String(), nil
}

func parseAuthHeader(header string) (AuthBits, error) {

	var ab AuthBits

	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.Trim(part, " "), "=", 2)
		if kv[0] == "APIKey" {
			if ab.APIKey != "" {
				return repeatedParameter(kv[0])
			}
			ab.APIKey = kv[1]
		} else if kv[0] == "Signature" {
			if ab.Signature != "" {
				return repeatedParameter(kv[0])
			}
			ab.Signature = kv[1]
		} else if kv[0] == "Timestamp" {
			if !ab.Timestamp.IsZero() {
				return repeatedParameter(kv[0])
			}
			t, err := time.Parse(time.RFC3339, kv[1])
			if err != nil {
				return parseError("Invalid timestamp. Requires RFC3339 format.")
			}
			ab.Timestamp = t
			ab.TimestampString = kv[1]
		} else {
			return parseError("Invalid parameter in header string")
		}
	}

	if !ab.IsValid() {
		return parseError("Missing parameter in header string")
	}

	return ab, nil
}

func parseError(s string) (AuthBits, error) {
	return AuthBits{}, errors.New(s)
}

func repeatedParameter(paramName string) (AuthBits, error) {
	return parseError(fmt.Sprintf("Repeated parameter: %q in header string", paramName))
}

func validateTimestamp(ts time.Time, options *Options) error {

	diffSeconds := time.Now().Sub(ts).Seconds()

	// Allow for about 10 seconds of difference, some servers are
	// ahead and some are behind
	if diffSeconds < (-10.0) {
		return errors.New("Timestamp out of range")
	}

	// do our best to normalize
	if diffSeconds < 0.0 {
		diffSeconds = 0.0
	}
	if options.SignatureExpiration != 0 {
		if diffSeconds > float64(options.SignatureExpiration) {
			return errors.New("Signature expired")
		}
	}

	return nil
}

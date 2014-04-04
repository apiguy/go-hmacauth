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

const maxNegativeFloat time.Duration = -10 * time.Second

type Options struct {
	SignedHeaders      []string
	SecretKey          keyLocator
	SignatureExpiresIn time.Duration
}

type HMACAuthError struct {
	Message string
}

func (e HMACAuthError) Error() string {
	return e.Message
}

type authBits struct {
	APIKey          string
	Signature       string
	TimestampString string
	Timestamp       time.Time
}

func (ab *authBits) IsValid() bool {
	return ab.APIKey != "" &&
		ab.Signature != "" &&
		!ab.Timestamp.IsZero()
}

func (ab *authBits) SetTimestamp(isoTime string) (err error) {
	ab.Timestamp, err = time.Parse(time.RFC3339, isoTime)
	if err == nil {
		ab.TimestampString = isoTime
	}
	return
}

func HMACAuth(options Options) middleware {
	// Validate options
	if options.SecretKey == nil {
		panic("HMACAuth Secret Key Locator Required")
	}

	return func(res http.ResponseWriter, req *http.Request) {
		var (
			err error
			ab  *authBits
		)

		if ab, err = parseAuthHeader(req.Header.Get("Authorization")); err == nil {
			if err = validateTimestamp(ab.Timestamp, &options); err == nil {
				var sts string
				if sts, err = stringToSign(req, &options, ab.TimestampString); err == nil {
					if sk := options.SecretKey(ab.APIKey); sk != "" {
						if ab.Signature != signString(sts, sk) {
							err = HMACAuthError{"Invalid Signature"}
						}
					} else {
						err = HMACAuthError{"Invalid APIKey"}
					}
				}
			}
		}

		if err != nil {
			http.Error(res, err.Error(), 401)
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

func parseAuthHeader(header string) (*authBits, error) {
	if header == "" {
		return nil, HMACAuthError{"Authorization Header Not Supplied"}
	}

	ab := new(authBits)
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.Trim(part, " "), "=", 2)
		if kv[0] == "APIKey" {
			if ab.APIKey != "" {
				return nil, repeatedParameterError(kv[0])
			}
			ab.APIKey = kv[1]
		} else if kv[0] == "Signature" {
			if ab.Signature != "" {
				return nil, repeatedParameterError(kv[0])
			}
			ab.Signature = kv[1]
		} else if kv[0] == "Timestamp" {
			if !ab.Timestamp.IsZero() {
				return nil, repeatedParameterError(kv[0])
			}
			if ab.SetTimestamp(kv[1]) != nil {
				return nil, HMACAuthError{"Invalid timestamp. Requires RFC3339 format."}
			}
		} else {
			return nil, HMACAuthError{"Invalid parameter in header string"}
		}
	}

	if !ab.IsValid() {
		return nil, HMACAuthError{"Missing parameter in header string"}
	}

	return ab, nil
}

func repeatedParameterError(paramName string) error {
	return HMACAuthError{fmt.Sprintf("Repeated parameter: %q in header string", paramName)}
}

func validateTimestamp(ts time.Time, options *Options) error {
	reqTime := time.Since(ts)

	// Allow for about `maxNegativeFloat` of difference, some servers are
	// ahead and some are behind
	if reqTime < maxNegativeFloat {
		return errors.New("Timestamp out of range")
	}

	if options.SignatureExpiresIn != 0 {
		if reqTime > options.SignatureExpiresIn {
			return errors.New("Signature expired")
		}
	}

	return nil
}

package hmacauth

import "fmt"

const (
	invalidTimestamp  = "Invalid timestamp. Requires RFC3339 format."
	invalidParameter  = "Invalid parameter in header string"
	missingParameter  = "Missing parameter in header string"
	tsOutOfRange      = "Timestamp out of range"
	signatureExpired  = "Signature expired"
	invalidSignature  = "Invalid Signature"
	invalidAPIKey     = "Invalid APIKey"
	secretKeyRequired = "HMACAuth Secret Key Locator Required"
	repeatedParameter = "Repeated parameter: %q in header string"
	missingHeader     = "Missing required header: %q"
)

type HMACAuthError struct {
	Message string
}

func (e HMACAuthError) Error() string {
	return e.Message
}

type RepeatedParameterError struct {
	ParameterName string
}

func (e RepeatedParameterError) Error() string {
	return fmt.Sprintf(repeatedParameter, e.ParameterName)
}

type HeaderMissingError struct {
	HeaderName string
}

func (e HeaderMissingError) Error() string {
	return fmt.Sprintf(missingHeader, e.HeaderName)
}

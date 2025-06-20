package solidgate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// defaultAPIURL is the default API endpoint
	defaultAPIURL = "https://pay.solidgate.com/api/v1/"

	// defaultRetryDelay is the default delay between retries for rate limiting
	defaultRetryDelay = 5 * time.Second

	// userAgent is the SDK's user agent string
	userAgent = "Go-SDK-1.7.0"
)

// ErrEmptyPayload is returned when the request payload is empty
var ErrEmptyPayload = errors.New("empty payload")

// API represents the SolidGate API client
type API struct {
	merchantID string
	privateKey string
	baseURI    string
	client     *http.Client
}

// Recurring performs a recurring payment request
func (api API) Recurring(data []byte) ([]byte, error) {
	return api.makeRequest("recurring", data)
}

// Refund performs a refund request
func (api API) Refund(data []byte) ([]byte, error) {
	return api.makeRequest("refund", data)
}

// Status checks the status of a transaction
func (api API) Status(data []byte) ([]byte, error) {
	return api.makeRequest("status", data)
}

// Resign performs a resign request
func (api API) Resign(data []byte) ([]byte, error) {
	return api.makeRequest("resign", data)
}

// Auth performs an authorization request
func (api API) Auth(data []byte) ([]byte, error) {
	return api.makeRequest("auth", data)
}

// Settle performs a settlement request
func (api API) Settle(data []byte) ([]byte, error) {
	return api.makeRequest("settle", data)
}

// Void performs a void request
func (api API) Void(data []byte) ([]byte, error) {
	return api.makeRequest("void", data)
}

// ArnCode retrieves the ARN code
func (api API) ArnCode(data []byte) ([]byte, error) {
	return api.makeRequest("arn-code", data)
}

// ApplePay processes an Apple Pay payment
func (api API) ApplePay(data []byte) ([]byte, error) {
	return api.makeRequest("apple-pay", data)
}

// GooglePay processes a Google Pay payment
func (api API) GooglePay(data []byte) ([]byte, error) {
	return api.makeRequest("google-pay", data)
}

// GenerateSignature generates a signature for the request
func (api API) GenerateSignature(data []byte) string {
	payloadData := api.merchantID + string(data) + api.merchantID
	keyForSign := []byte(api.privateKey)

	h := hmac.New(sha512.New, keyForSign)
	h.Write([]byte(payloadData))

	return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))
}

// makeRequest performs an HTTP request to the Solidgate API
func (api API) makeRequest(endpoint string, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}

	req, err := api.newRequest(endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	res, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusServiceUnavailable {
		time.Sleep(defaultRetryDelay)
		return api.makeRequest(endpoint, payload)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return body, nil
}

// newRequest creates a new HTTP request with proper headers
func (api API) newRequest(endpoint string, payload []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, api.baseURI+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Signature", api.GenerateSignature(payload))
	req.Header.Set("Merchant", api.merchantID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	return req, nil
}

// FormMerchantData prepares merchant data for form initialization
func (api API) FormMerchantData(data []byte) (*FormInitDTO, error) {
	if len(data) == 0 {
		return nil, ErrEmptyPayload
	}

	secretKey := []byte(api.privateKey)[:32]
	encryptedData, err := EncryptCBC(secretKey, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	encoded := base64.URLEncoding.EncodeToString(encryptedData)
	signature := api.GenerateSignature([]byte(encoded))

	return &FormInitDTO{
		PaymentIntent: encoded,
		Merchant:      api.merchantID,
		Signature:     signature,
	}, nil
}

// FormUpdate prepares data for form update
func (api API) FormUpdate(data []byte) (*FormUpdateDTO, error) {
	if len(data) == 0 {
		return nil, ErrEmptyPayload
	}

	secretKey := []byte(api.privateKey)[:32]
	encryptedData, err := EncryptCBC(secretKey, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	encoded := base64.URLEncoding.EncodeToString(encryptedData)
	signature := api.GenerateSignature([]byte(encoded))

	return &FormUpdateDTO{
		PartialIntent: encoded,
		Signature:     signature,
	}, nil
}

// FormResign prepares data for form resignation
func (api API) FormResign(data []byte) (*FormResignDTO, error) {
	if len(data) == 0 {
		return nil, ErrEmptyPayload
	}

	secretKey := []byte(api.privateKey)[:32]
	encryptedData, err := EncryptCBC(secretKey, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	encoded := base64.URLEncoding.EncodeToString(encryptedData)
	signature := api.GenerateSignature([]byte(encoded))

	return &FormResignDTO{
		ResignIntent: encoded,
		Merchant:     api.merchantID,
		Signature:    signature,
	}, nil
}

// NewAPI creates a new SolidGate API client
func NewAPI(merchantID, privateKey string, baseURI *string) (*API, error) {
	if len(privateKey) < 32 {
		return nil, fmt.Errorf("private key must be at least 32 bytes long")
	}

	uri := defaultAPIURL
	if baseURI != nil {
		uri = *baseURI
	}

	return &API{
		merchantID: merchantID,
		privateKey: privateKey,
		baseURI:    uri,
		client: &http.Client{
			Timeout: 50 * time.Second,
		},
	}, nil
}

package solidgate

import (
	"testing"
)

func TestApi_GenerateSignature(t *testing.T) {
	api, err := NewAPI("test-merchant", "test-key-that-is-longer-than-32-bytes-for-testing", nil)
	if err != nil {
		t.Fatalf("Failed to create API: %v", err)
	}
	data := []byte(`{"test":"data"}`)

	signature := api.GenerateSignature(data)
	if signature == "" {
		t.Error("GenerateSignature returned empty string")
	}
}

func TestApi_FormMerchantData(t *testing.T) {
	api, err := NewAPI("test-merchant", "test-key-that-is-longer-than-32-bytes-for-testing", nil)
	if err != nil {
		t.Fatalf("Failed to create API: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid data",
			data:    []byte(`{"test":"data"}`),
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := api.FormMerchantData(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormMerchantData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("FormMerchantData() returned nil result")
			}
		})
	}
}

func TestApi_FormUpdate(t *testing.T) {
	api, err := NewAPI("test-merchant", "test-key-that-is-longer-than-32-bytes-for-testing", nil)
	if err != nil {
		t.Fatalf("Failed to create API: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid data",
			data:    []byte(`{"test":"data"}`),
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := api.FormUpdate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("FormUpdate() returned nil result")
			}
		})
	}
}

func TestApi_FormResign(t *testing.T) {
	api, err := NewAPI("test-merchant", "test-key-that-is-longer-than-32-bytes-for-testing", nil)
	if err != nil {
		t.Fatalf("Failed to create API: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid data",
			data:    []byte(`{"test":"data"}`),
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := api.FormResign(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormResign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("FormResign() returned nil result")
			}
		})
	}
}

func TestNewSolidGateApi(t *testing.T) {
	tests := []struct {
		name       string
		merchantID string
		privateKey string
		baseURI    *string
		wantErr    bool
	}{
		{
			name:       "valid configuration",
			merchantID: "test-merchant",
			privateKey: "test-key-that-is-longer-than-32-bytes-for-testing",
			baseURI:    nil,
			wantErr:    false,
		},
		{
			name:       "custom base URI",
			merchantID: "test-merchant",
			privateKey: "test-key-that-is-longer-than-32-bytes-for-testing",
			baseURI:    stringPtr("https://custom.api/"),
			wantErr:    false,
		},
		{
			name:       "short private key",
			merchantID: "test-merchant",
			privateKey: "short-key",
			baseURI:    nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, err := NewAPI(tt.merchantID, tt.privateKey, tt.baseURI)
			if tt.wantErr {
				if err == nil {
					t.Error("NewSolidGateApi expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("NewSolidGateApi unexpected error: %v", err)
			}
			if api == nil {
				t.Error("NewSolidGateApi returned nil")
			}
			if api.merchantID != tt.merchantID {
				t.Errorf("merchantID = %v, want %v", api.merchantID, tt.merchantID)
			}
			if api.privateKey != tt.privateKey {
				t.Errorf("privateKey = %v, want %v", api.privateKey, tt.privateKey)
			}
			if tt.baseURI != nil && api.baseURI != *tt.baseURI {
				t.Errorf("baseURI = %v, want %v", api.baseURI, *tt.baseURI)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

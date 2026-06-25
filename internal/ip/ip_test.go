package ip

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestGetSubdomain(t *testing.T) {
	// Backup original transport and restore afterwards
	origTransport := http.DefaultClient.Transport
	defer func() {
		http.DefaultClient.Transport = origTransport
	}()

	tests := []struct {
		name       string
		ipResponse string
		domain     string
		want       string
		wantErr    bool
	}{
		{
			name:       "IPv4 with dot domain",
			ipResponse: "127.0.0.1",
			domain:     ".example.com",
			want:       "dns-7f000001.example.com",
		},
		{
			name:       "IPv4 without dot domain",
			ipResponse: "8.8.8.8",
			domain:     "example.com",
			want:       "dns-08080808.example.com",
		},
		{
			name:       "Invalid IP response",
			ipResponse: "not-an-ip",
			domain:     "example.com",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http.DefaultClient.Transport = &mockRoundTripper{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(tt.ipResponse)),
					}, nil
				},
			}

			got, err := GetSubdomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetSubdomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetSubdomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

package spotlib

import (
	"context"
	"testing"
)

func TestDecodeBase32IP(t *testing.T) {
	tests := []struct {
		encoded string
		want    string
		wantErr bool
	}{
		// Test IPv4 decoding (verified from actual hostnames)
		{"EP3E7PQ", "35.246.79.190", false},
		{"EKMA2UY", "34.152.13.83", false},
		// Test round-trip encoding/decoding
		{"YCUACAI", "192.168.1.1", false},
		{"BIAAAAI", "10.0.0.1", false},
		// Invalid cases
		{"ABC", "", true}, // too short for valid IP
	}

	for _, tt := range tests {
		got, err := decodeBase32IP(tt.encoded)
		if (err != nil) != tt.wantErr {
			t.Errorf("decodeBase32IP(%q) error = %v, wantErr %v", tt.encoded, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("decodeBase32IP(%q) = %v, want %v", tt.encoded, got, tt.want)
		}
	}
}

func TestGdnsResolverLookupHost(t *testing.T) {
	r := newGdnsResolver()

	// Test with the examples from the log:
	// ep3e7pq.g-dns.net and ekma2uy.g-dns.net
	tests := []struct {
		host    string
		wantLen int
		wantIPs []string
	}{
		{"ep3e7pq.g-dns.net", 1, []string{"35.246.79.190"}},
		{"ekma2uy.g-dns.net", 1, []string{"34.152.13.83"}},
		{"EP3E7PQ.G-DNS.NET", 1, []string{"35.246.79.190"}}, // case insensitive
		// Dual IP format with hyphen separator
		{"ycuacai-biaaaai.g-dns.net", 2, []string{"192.168.1.1", "10.0.0.1"}},
	}

	for _, tt := range tests {
		got, err := r.LookupHost(context.Background(), tt.host)
		if err != nil {
			t.Errorf("LookupHost(%q) error = %v", tt.host, err)
			continue
		}
		if len(got) != tt.wantLen {
			t.Errorf("LookupHost(%q) returned %d addresses, want %d: %v", tt.host, len(got), tt.wantLen, got)
		}
		for i, wantIP := range tt.wantIPs {
			if i < len(got) && got[i] != wantIP {
				t.Errorf("LookupHost(%q)[%d] = %v, want %v", tt.host, i, got[i], wantIP)
			}
		}
		t.Logf("LookupHost(%q) = %v", tt.host, got)
	}
}

func TestDecodeGdnsExamples(t *testing.T) {
	r := newGdnsResolver()

	// Decode and print the actual IPs from the log examples
	tests := []string{
		"ep3e7pq.g-dns.net",
		"ekma2uy.g-dns.net",
	}

	for _, host := range tests {
		ips, err := r.decodeGdns(host)
		if err != nil {
			t.Logf("decodeGdns(%q) error = %v", host, err)
		} else {
			t.Logf("decodeGdns(%q) = %v", host, ips)
		}
	}
}

func TestBase32Encoding(t *testing.T) {
	// Test encoding to verify our decoder works correctly
	// IPv4: 4 bytes -> 7 base32 chars (without padding)
	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	for _, ip := range testIPs {
		// Encode
		ipBytes := []byte{192, 168, 1, 1}
		if ip == "10.0.0.1" {
			ipBytes = []byte{10, 0, 0, 1}
		} else if ip == "172.16.0.1" {
			ipBytes = []byte{172, 16, 0, 1}
		}
		encoded := b32e.EncodeToString(ipBytes)
		t.Logf("IP %s encodes to %s", ip, encoded)

		// Decode back
		decoded, err := decodeBase32IP(encoded)
		if err != nil {
			t.Errorf("Failed to decode %s: %v", encoded, err)
			continue
		}
		t.Logf("Decoded %s back to %s", encoded, decoded)
	}
}

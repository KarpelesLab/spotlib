package spotlib

import (
	"context"
	"encoding/base32"
	"net"
	"strings"
)

// base32 encoding used for g-dns.net hostnames (RFC 4648 without padding)
var b32e = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

// gdnsResolver is a custom DNS resolver that intercepts lookups for g-dns.net
// domains and decodes base32-encoded IP addresses directly, avoiding actual
// DNS queries that may fail on misconfigured DNS servers.
type gdnsResolver struct {
	fallback *net.Resolver
}

// newGdnsResolver creates a new resolver that handles g-dns.net lookups.
func newGdnsResolver() *gdnsResolver {
	return &gdnsResolver{
		fallback: net.DefaultResolver,
	}
}

// LookupHost resolves hostnames. For g-dns.net domains, it decodes the base32
// encoded IP addresses directly. For other domains, it falls back to the
// default resolver.
func (r *gdnsResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// Check if this is a g-dns.net domain
	if strings.HasSuffix(strings.ToLower(host), ".g-dns.net") {
		return r.decodeGdns(host)
	}
	return r.fallback.LookupHost(ctx, host)
}

// decodeGdns decodes a g-dns.net hostname into IP addresses.
// Format: <base32-ipv4>.g-dns.net or <base32-ipv4>-<base32-ipv6>.g-dns.net
// or <base32-ipv6>.g-dns.net
func (r *gdnsResolver) decodeGdns(host string) ([]string, error) {
	// Remove the .g-dns.net suffix (case-insensitive)
	host = strings.ToLower(host)
	encoded := strings.TrimSuffix(host, ".g-dns.net")

	var results []string

	// Check for hyphen separator (both IPv4 and IPv6)
	parts := strings.Split(encoded, "-")

	for _, part := range parts {
		if part == "" {
			continue
		}

		ip, err := decodeBase32IP(part)
		if err != nil {
			// If decoding fails, fall back to regular DNS
			return net.DefaultResolver.LookupHost(context.Background(), host+".g-dns.net")
		}
		results = append(results, ip)
	}

	if len(results) == 0 {
		// Fall back to regular DNS if no valid IPs decoded
		return net.DefaultResolver.LookupHost(context.Background(), host+".g-dns.net")
	}

	return results, nil
}

// decodeBase32IP decodes a base32-encoded IP address.
// 4 bytes = IPv4, 16 bytes = IPv6
func decodeBase32IP(encoded string) (string, error) {
	// Base32 is case-insensitive, but our encoder uses uppercase
	encoded = strings.ToUpper(encoded)

	data, err := b32e.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	switch len(data) {
	case 4:
		// IPv4
		ip := net.IP(data)
		return ip.String(), nil
	case 16:
		// IPv6
		ip := net.IP(data)
		return ip.String(), nil
	default:
		return "", &net.DNSError{
			Err:  "invalid encoded IP length",
			Name: encoded,
		}
	}
}

// Dial creates a network connection, using the custom resolver for g-dns.net domains.
func (r *gdnsResolver) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// Resolve the hostname
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	// Try each resolved address
	var lastErr error
	for _, addr := range addrs {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addr, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, &net.DNSError{
		Err:  "no addresses found",
		Name: host,
	}
}

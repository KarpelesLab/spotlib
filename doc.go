// Package spotlib provides a client implementation for the Spot secure messaging protocol.
//
// Spotlib enables secure, end-to-end encrypted communication between clients through
// the Spot network. It handles connection management, cryptographic identity, message
// routing, and provides both request-response and fire-and-forget messaging patterns.
//
// # Basic Usage
//
// Create a new client with an optional private key for identity:
//
//	client, err := spotlib.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Wait for the client to come online:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := client.WaitOnline(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Sending Messages
//
// Send an encrypted query and wait for a response:
//
//	response, err := client.Query(ctx, "k.targetID/endpoint", []byte("payload"))
//
// Send a one-way encrypted message:
//
//	err := client.SendTo(ctx, "k.targetID/endpoint", []byte("payload"))
//
// # Receiving Messages
//
// Register a handler for incoming messages on an endpoint:
//
//	client.SetHandler("myendpoint", func(msg *spotproto.Message) ([]byte, error) {
//	    // Process message and return response
//	    return []byte("response"), nil
//	})
//
// # PacketConn Interface
//
// For UDP-like communication, use ListenPacket to get a net.PacketConn:
//
//	conn, err := client.ListenPacket("udp-endpoint")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
//
// # Identity and Addressing
//
// Each client has a cryptographic identity represented by an IDCard. The client's
// address (TargetId) is derived from the SHA-256 hash of its public key and has
// the format "k.<base64url-encoded-hash>".
//
// Messages to key-based addresses (starting with "k.") are automatically encrypted
// and signed. The recipient's public key is retrieved and cached automatically.
package spotlib

[![GoDoc](https://godoc.org/github.com/KarpelesLab/spotlib?status.svg)](https://godoc.org/github.com/KarpelesLab/spotlib)

# spotlib

Spot connection library for Go. Enables secure, end-to-end encrypted communication between clients through the Spot network.

## Features

- End-to-end encrypted messaging using cryptographic identity cards
- Automatic connection management with reconnection support
- Request-response and fire-and-forget messaging patterns
- `net.PacketConn` interface for UDP-like communication
- Event-based status notifications
- ID card caching with automatic updates

## Installation

```bash
go get github.com/KarpelesLab/spotlib
```

## Quick Start

### Creating a Client

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/KarpelesLab/spotlib"
)

func main() {
    // Create a new client with an ephemeral key
    client, err := spotlib.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Wait for the client to come online
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    if err := client.WaitOnline(ctx); err != nil {
        log.Fatal("failed to connect:", err)
    }

    log.Println("Connected! Client ID:", client.TargetId())
}
```

### Using a Persistent Identity

The easiest way to maintain the same identity across restarts is to use `NewDiskStore`:

```go
// Create a disk store that persists keys to ~/.config/spot/ (or equivalent)
store, err := spotlib.NewDiskStore()
if err != nil {
    log.Fatal(err)
}

// Create client with the stored keychain
client, err := spotlib.New(store.Keychain())
```

The disk store automatically:
- Creates the storage directory if it doesn't exist
- Generates a new ECDSA P-256 key if no keys exist
- Loads existing keys on subsequent runs
- Stores keys in PEM-encoded PKCS#8 format as `id_<type>.key` files

You can also specify a custom path:

```go
store, err := spotlib.NewDiskStoreWithPath("/path/to/keys")
```

Alternatively, manage keys manually:

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"

    "github.com/KarpelesLab/spotlib"
)

// Generate or load your private key
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Create client with the key
client, err := spotlib.New(privateKey)
```

You can also pass a `*cryptutil.Keychain` for more advanced key management.

### Sending Messages

#### Query (Request-Response)

```go
// Send an encrypted query and wait for response
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

response, err := client.Query(ctx, "k.recipientID/endpoint", []byte("hello"))
if err != nil {
    log.Fatal(err)
}
log.Println("Response:", string(response))
```

#### Send (Fire-and-Forget)

```go
// Send a one-way encrypted message
err := client.SendTo(ctx, "k.recipientID/endpoint", []byte("hello"))
```

### Receiving Messages

Register handlers for incoming messages on specific endpoints:

```go
import "github.com/KarpelesLab/spotproto"

client.SetHandler("myendpoint", func(msg *spotproto.Message) ([]byte, error) {
    log.Printf("Received from %s: %s", msg.Sender, string(msg.Body))

    // Return a response (or nil for no response)
    return []byte("acknowledged"), nil
})
```

### Monitoring Connection Status

```go
// Listen for status changes
go func() {
    for ev := range client.Events.On("status") {
        status := emitter.Arg[int](ev, 0)
        if status == 1 {
            log.Println("Online!")
        } else {
            log.Println("Offline")
        }
    }
}()

// Or wait for online status
client.Events.On("online") // triggered when going online
```

### PacketConn Interface

For UDP-like communication patterns, use the `net.PacketConn` interface:

```go
conn, err := client.ListenPacket("udp-endpoint")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Send data
addr := spotlib.SpotAddr("k.recipientID/udp-endpoint")
conn.WriteTo([]byte("hello"), addr)

// Receive data
buf := make([]byte, 4096)
n, remoteAddr, err := conn.ReadFrom(buf)
if err != nil {
    log.Fatal(err)
}
log.Printf("Received %d bytes from %s", n, remoteAddr)
```

### Blob Storage

Store and retrieve encrypted data that persists across sessions:

```go
// Store data (encrypted, only readable by this client)
err := client.StoreBlob(ctx, "my-key", []byte("secret data"))

// Retrieve data
data, err := client.FetchBlob(ctx, "my-key")

// Delete data
err := client.StoreBlob(ctx, "my-key", nil)
```

Note: Blob storage is best-effort and has a size limit of ~49KB. Data may be purged after extended periods without access.

### Group Membership

```go
// Get members of a group
members, err := client.GetGroupMembers(ctx, groupKey)
for _, member := range members {
    log.Println("Member:", member)
}
```

### Server Time

```go
serverTime, err := client.GetTime(ctx)
log.Println("Server time:", serverTime)
```

## Addressing

Spot uses the following address formats:

| Prefix | Description | Example |
|--------|-------------|---------|
| `k.` | Key-based address (encrypted) | `k.ABC123.../endpoint` |
| `@/` | System endpoints | `@/time` |

Messages to `k.` addresses are automatically encrypted and signed. The recipient's public key is fetched and cached automatically.

## Client Options

The `New()` function accepts various optional parameters:

```go
client, err := spotlib.New(
    privateKey,                        // crypto.Signer for identity
    keychain,                          // *cryptutil.Keychain
    eventHub,                          // *emitter.Hub for custom event handling
    map[string]spotlib.MessageHandler{ // Initial handlers
        "endpoint": myHandler,
    },
    map[string]string{                 // Metadata for ID card
        "name": "my-client",
    },
)
```

## Default Handlers

The client registers these handlers automatically:

| Endpoint | Description |
|----------|-------------|
| `ping` | Echo service for connectivity testing |
| `version` | Returns library and Go runtime version |
| `finger` | Returns the client's signed identity |
| `check_update` | Triggers update check events |
| `idcard_update` | Handles ID card update notifications |

## API Reference

### Client Methods

| Method | Description |
|--------|-------------|
| `New(params...)` | Create a new client |
| `Close()` | Gracefully shut down the client |
| `WaitOnline(ctx)` | Block until connected |
| `Query(ctx, target, body)` | Send request and wait for response |
| `SendTo(ctx, target, payload)` | Send one-way message |
| `SetHandler(endpoint, handler)` | Register message handler |
| `ListenPacket(name)` | Get net.PacketConn interface |
| `TargetId()` | Get client's address string |
| `IDCard()` | Get client's identity card |
| `ConnectionCount()` | Get (total, online) connection counts |
| `GetIDCard(ctx, hash)` | Fetch remote identity card |
| `StoreBlob(ctx, key, value)` | Store encrypted data |
| `FetchBlob(ctx, key)` | Retrieve encrypted data |
| `GetTime(ctx)` | Get server time |
| `GetGroupMembers(ctx, key)` | List group members |

### Storage

| Type/Function | Description |
|---------------|-------------|
| `ClientData` | Interface for providing client identity (requires `Keychain()` method) |
| `NewDiskStore()` | Create disk store at default path (`~/.config/spot/`) |
| `NewDiskStoreWithPath(path)` | Create disk store at custom path |
| `(*diskStore).Keychain()` | Get keychain with loaded keys |
| `(*diskStore).Path()` | Get storage directory path |
| `(*diskStore).AddKey(key, type)` | Add and persist a new key |

## License

See LICENSE file for details.

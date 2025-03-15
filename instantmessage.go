// Package spotlib provides a client implementation for the Spot secure messaging protocol
package spotlib

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/KarpelesLab/cryptutil"
	"github.com/google/uuid"
)

// InstantMessage represents a message with metadata, content, and cryptographic information
type InstantMessage struct {
	ID        uuid.UUID // Unique message identifier
	Flags     uint64    // Message flags for special handling
	Recipient string    // Target recipient identifier
	Sender    string    // Source sender identifier
	Body      []byte    // Actual message content
	Encrypted bool      // Whether the message was encrypted
	SignedBy  [][]byte  // Contains the public keys that signed the message when decoding
}

// DecodeInstantMessage extracts an InstantMessage from a cryptographic bottle
// It verifies the contents and populates metadata fields based on the bottle headers
func DecodeInstantMessage(buf []byte, res *cryptutil.OpenResult, err error) (*InstantMessage, error) {
	if err != nil {
		return nil, err
	}
	b := res.Last()

	im := &InstantMessage{
		Body: buf,
	}

	if v, ok := b.Header["mid"].([]byte); ok {
		copy(im.ID[:], v)
	} else {
		return nil, errors.New("invalid message, message ID is missing")
	}
	if v, ok := b.Header["flg"].(uint64); ok {
		im.Flags = v
	}
	if v, ok := b.Header["dst"].(string); ok {
		im.Recipient = v
	}
	if v, ok := b.Header["rto"].(string); ok {
		im.Sender = v
	}

	im.Encrypted = res.Decryption > 0
	for _, sig := range res.Signatures {
		im.SignedBy = append(im.SignedBy, sig.Signer)
	}

	return im, nil
}

// Bottle converts the InstantMessage into a cryptographic bottle for secure transmission
func (im *InstantMessage) Bottle() *cryptutil.Bottle {
	b := cryptutil.NewBottle(im.Body)
	b.Header["mid"] = im.ID[:] // message id
	if im.Flags != 0 {
		b.Header["flg"] = im.Flags
	}
	if im.Recipient != "" {
		b.Header["dst"] = im.Recipient
	}
	if im.Sender != "" {
		b.Header["rto"] = im.Sender // "reply to"
	}
	return b
}

// MarshalBinary implements the BinaryMarshaler interface for serialization
func (im *InstantMessage) MarshalBinary() ([]byte, error) {
	return im.Bytes(), nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface for deserialization
func (im *InstantMessage) UnmarshalBinary(r []byte) error {
	_, err := im.ReadFrom(bytes.NewReader(r))
	return err
}

// ReadFrom implements the ReaderFrom interface for streaming deserialization
func (im *InstantMessage) ReadFrom(r io.Reader) (int64, error) {
	rb := bufio.NewReader(r)

	n, err := io.ReadFull(rb, im.ID[:])
	if err != nil {
		return int64(n), err
	}
	im.Flags, err = binary.ReadUvarint(rb)
	if err != nil {
		return int64(n), err
	}
	return int64(n), nil
}

// Bytes serializes the InstantMessage into a byte array for transmission
func (im *InstantMessage) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(im.ID[:])
	buf.Write(binary.AppendUvarint(nil, im.Flags))
	writeVarString(buf, []byte(im.Recipient))
	writeVarString(buf, []byte(im.Sender))
	buf.Write(im.Body)
	return buf.Bytes()
}

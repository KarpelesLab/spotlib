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

type InstantMessage struct {
	ID        uuid.UUID
	Flags     uint64
	Recipient string
	Sender    string
	Body      []byte
	Encrypted bool
	SignedBy  [][]byte // contains the public keys that signed the message when decoding
}

// DecodeInstantMessage will return a InstantMessage for a given bottle, after checking the source and various details
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

func (im *InstantMessage) MarshalBinary() ([]byte, error) {
	return im.Bytes(), nil
}

func (im *InstantMessage) UnmarshalBinary(r []byte) error {
	_, err := im.ReadFrom(bytes.NewReader(r))
	return err
}

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

func (im *InstantMessage) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(im.ID[:])
	buf.Write(binary.AppendUvarint(nil, im.Flags))
	writeVarString(buf, []byte(im.Recipient))
	writeVarString(buf, []byte(im.Sender))
	buf.Write(im.Body)
	return buf.Bytes()
}

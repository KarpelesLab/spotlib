package spotlib_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotlib"
)

func TestClient(t *testing.T) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	c, err := spotlib.New(map[string]string{"testmode": "spotlib"})
	if err != nil {
		t.Fatalf("failed to perfor mtest: %s", err)
		return
	}
	res, err := c.QueryTimeout(10*time.Second, "@/version", nil)
	if err != nil {
		t.Fatalf("failed to request version: %s", err)
		return
	}
	log.Printf("server version = %s", res)

	// attempt to get our own IDcard
	idc, err := c.GetIDCard(context.Background(), cryptutil.Hash(c.IDCard().Self, sha256.New))
	if err != nil {
		t.Fatalf("failed to fetch own id: %s", err)
		return
	}
	if !bytes.Equal(idc.Self, c.IDCard().Self) {
		t.Fatalf("invalid self value for idcard, %x != %x", idc.Self, c.IDCard().Self)
	}
	log.Printf("got self id = %x", cryptutil.Hash(idc.Self, sha256.New))

	// send an encrypted message to ourselves
}

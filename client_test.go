package spotlib_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"
)

func TestClient(t *testing.T) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	handlers := map[string]spotlib.MessageHandler{
		"test2": func(msg *spotproto.Message) ([]byte, error) {
			if !msg.IsEncrypted() {
				return nil, errors.New("only accepts encrypted messages")
			}
			res := strings.ToUpper(string(msg.Body))
			return []byte(res), nil
		},
	}

	c, err := spotlib.New(map[string]string{"testmode": "spotlib"}, handlers)
	if err != nil {
		t.Fatalf("failed to perfor mtest: %s", err)
		return
	}
	c.WaitOnline(context.Background())

	res, err := c.QueryTimeout(10*time.Second, "@/version", nil)
	if err != nil {
		t.Fatalf("failed to request version: %s", err)
		return
	}
	log.Printf("server version = %s", res)

	var tim time.Time
	spotlib.WithTimeout(context.Background(), 30*time.Second, func(ctx context.Context) {
		tim, err = c.GetTime(ctx)
	})
	if err != nil {
		t.Fatalf("failed to request time: %s", err)
	}
	log.Printf("server time: %s", tim)

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

	hQ := make(chan []byte, 2)

	c.SetHandler("test1", func(msg *spotproto.Message) ([]byte, error) {
		hQ <- msg.Body
		return nil, nil
	})

	// send an encrypted message to ourselves
	err = c.SendTo(context.Background(), c.TargetId()+"/test1", []byte("hello world"))
	if err != nil {
		t.Fatalf("failed to send msg: %s", err)
	}
	dat := <-hQ
	if string(dat) != "hello world" {
		t.Fatalf("bad message: %s", dat)
	}

	v, err := c.Query(context.Background(), c.TargetId()+"/test2", []byte("hello world"))
	if err != nil {
		t.Fatalf("failed to send msg: %s", err)
	} else if string(v) != "HELLO WORLD" {
		t.Fatalf("invalid response to query: %s", v)
	}

	c2, err := spotlib.New(map[string]string{"testmode": "spotlib"})
	if err != nil {
		t.Fatalf("failed to perform second co: %s", err)
		return
	}
	c2.WaitOnline(context.Background())

	// attempt to query c via c2
	v, err = c2.Query(context.Background(), c.TargetId()+"/test2", []byte("hello from afar"))
	if err != nil {
		t.Fatalf("failed to send msg: %s", err)
	} else if string(v) != "HELLO FROM AFAR" {
		t.Fatalf("invalid response to query: %s", v)
	}

	// attempt to ping c2
	v, err = c.Query(context.Background(), c2.TargetId()+"/ping", []byte("ping buffer"))
	if err != nil {
		t.Fatalf("failed to send msg: %s", err)
	} else if string(v) != "ping buffer" {
		t.Fatalf("invalid response to query: %s", v)
	}

	v, err = c.Query(context.Background(), c2.TargetId()+"/version", nil)
	if err != nil {
		t.Fatalf("failed to send msg: %s", err)
	}
	log.Printf("got version = %s", v)

	// let's try storing some random data
	buf := []byte("Hello this is a test buffer")
	err = c.StoreBlob(context.Background(), "test.txt", buf)
	if err != nil {
		t.Fatalf("failed to store file: %s", err)
	}

	// retrieve it
	buf2, err := c.FetchBlob(context.Background(), "test.txt")
	if err != nil {
		t.Fatalf("failed to fetch file: %s", err)
	} else if !bytes.Equal(buf, buf2) {
		t.Fatalf("buf is not equal")
	}
}

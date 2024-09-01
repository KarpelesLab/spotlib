package spotlib_test

import (
	"log"
	"log/slog"
	"os"
	"testing"

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
	res, err := c.Query("@/version", nil)
	if err != nil {
		t.Fatalf("failed to request version: %s", err)
		return
	}
	log.Printf("server version = %s", res)
}

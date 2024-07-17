package spotlib

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/rest"
)

// RegId will attempt to sign & register the given id card
func RegId(id *cryptutil.IDCard, sig crypto.Signer) ([]byte, error) {
	dat, err := id.Sign(rand.Reader, sig)
	if err != nil {
		return nil, err
	}

	b64dat := base64.RawURLEncoding.EncodeToString(dat)
	_, err = rest.Do(context.Background(), "IDCard:publish", "POST", rest.Param{"token": b64dat})
	return dat, err
}

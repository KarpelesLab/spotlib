package spotlib

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/rest"
	"github.com/fxamacker/cbor/v2"
)

// RegId will attempt to sign & register the given id card
func RegId(id *cryptutil.IDCard, sig crypto.Signer) ([]byte, error) {
	grps, err := fetchGroups(id)
	if err != nil {
		log.Printf("failed to fetch groups: %s", err)
	} else {
		id.Groups = grps
	}

	dat, err := id.Sign(rand.Reader, sig)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b64dat := base64.RawURLEncoding.EncodeToString(dat)
	_, err = rest.Do(ctx, "IDCard:publish", "POST", rest.Param{"token": b64dat})
	return dat, err
}

func fetchGroups(id *cryptutil.IDCard) ([]*cryptutil.Membership, error) {
	var l []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := sha256.Sum256(id.Self)

	err := rest.Apply(ctx, "IDCard/Membership:fetch", "GET", rest.Param{"hash": hex.EncodeToString(h[:])}, &l)
	if err != nil {
		return nil, err
	}

	var res []*cryptutil.Membership

	for _, dat := range l {
		buf, err := base64.RawURLEncoding.DecodeString(dat)
		if err != nil {
			log.Printf("failed to decode group: %s", err)
			continue
		}
		var m *cryptutil.Membership
		err = cbor.Unmarshal(buf, &m)
		if err != nil {
			log.Printf("failed to unmarshal group: %s", err)
			continue
		}
		err = m.Verify(nil)
		if err != nil {
			log.Printf("failed to verify group: %s", err)
			continue
		}
		res = append(res, m)
	}
	return res, nil
}

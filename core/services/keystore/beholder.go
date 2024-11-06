package keystore

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

func BuildBeholderAuth(keyStore Master) (map[string]string, string, error) {
	csaKeys, err := keyStore.CSA().GetAll()
	if err != nil {
		return nil, "", err
	}
	csaKey := csaKeys[0]
	csaPrivKey := csaKey.Raw().Bytes()
	csaSigner := func(data []byte) []byte {
		return ed25519.Sign(csaPrivKey, data)
	}
	beholderAuthHeaders := beholder.BuildAuthHeaders(csaSigner, csaKey.PublicKey)

	return beholderAuthHeaders, hex.EncodeToString(csaKey.PublicKey), nil
}

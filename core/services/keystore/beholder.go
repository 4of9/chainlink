package keystore

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

func BuildBeholderAuth(keyStore Master) (authHeaders map[string]string, pubKeyHex string, err error) {
	csaKeys, err := keyStore.CSA().GetAll()
	if err != nil {
		return nil, "", err
	}
	csaKey := csaKeys[0]
	csaPrivKey := csaKey.Raw().Bytes()
	csaSigner := func(data []byte) []byte {
		return ed25519.Sign(csaPrivKey, data)
	}
	authHeaders = beholder.BuildAuthHeaders(csaSigner, csaKey.PublicKey)
	pubKeyHex = hex.EncodeToString(csaKey.PublicKey)
	return
}

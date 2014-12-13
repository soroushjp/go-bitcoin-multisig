package multisig

import (
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	GenerateKeys(1, true)
	publicKey, err := hex.DecodeString(PublicKeyHex)
	if err != nil {
		t.Error(err)
	}
	err = btcutils.CheckPublicKeyIsValid(publicKey)
	if err != nil {
		t.Error(err)
	}
}

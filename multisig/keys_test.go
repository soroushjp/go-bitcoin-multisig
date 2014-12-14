package multisig

import (
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	privateKeyWIFs, publicKeyHexs, publicAddresses := generateKeys(1)
	publicKey, err := hex.DecodeString(publicKeyHexs[0])
	if err != nil {
		t.Error(err)
	}
	err = btcutils.CheckPublicKeyIsValid(publicKey)
	if err != nil {
		t.Error(err)
	}
	if privateKeyWIFs[0] == "" {
		t.Error("Generated private key cannot be empty.")
	}
	if len(privateKeyWIFs[0]) != 51 {
		t.Error("Generated private key is wrong length. Should be 51 characters long.")
	}
	if privateKeyWIFs[0][0:1] != "5" {
		t.Error("Generated private key has wrong prefix. Should be '5' for mainnet private key.")
	}
	//Testing for publicAddress could be made more robust in future by checking SHA256 checksum matches address.
	if publicAddresses[0] == "" {
		t.Error("Generated public address cannot be empty.")
	}
	if len(publicAddresses[0]) < 26 || len(publicAddresses[0]) > 34 {
		t.Error("Generated public address is wrong length. Should be betweeen 26 and 34 characters.")
	}
	if publicAddresses[0][0:1] != "1" {
		t.Error("Generated public address has wrong prefix. Should be '5' for mainnet P2PKH addresses.")
	}
}

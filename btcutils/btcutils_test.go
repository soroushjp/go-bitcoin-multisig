package btcutils

import (
	"encoding/hex"
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"testing"
)

func TestHash160(t *testing.T) {
	hash, err := Hash160([]byte("teststring"))
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(hash) != "51d9ac622c2133ca4aaf58d4a4239526eb42c348" {
		t.Error("Deterministic hash RIPEMD160(SHA256(data)) different from expected hash.")
	}
}

func TestNewMOfNRedeemScript(t *testing.T) {
	testPublicKeyStrings := []string{
		"0446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce9",
		"04704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da124",
		"04b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d28",
	}
	testM := 2
	testN := 3
	testRedeemScript := "52410446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce94104704e19d4fc234a42d707d41053c87011f990b564949532d72cab009e136bd60d7d0602f925fce79da77c0dfef4a49c6f44bd0540faef548e37557d74b36da1244104b75a8cb10fd3f1785addbafdb41b409ecd6ffd50d5ad71d8a3cdc5503bcb35d3d13cdf23f6d0eb6ab88446276e2ba5b92d8786da7e5c0fb63aafb62f87443d2853ae"

	publicKeys := make([][]byte, len(testPublicKeyStrings))
	for i, publicKeyString := range testPublicKeyStrings {
		publicKeys[i], _ = hex.DecodeString(publicKeyString) //Get private keys as slice of raw bytes
	}
	testMOfNRedeemScript, err := NewMOfNRedeemScript(testM, testN, publicKeys)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(testMOfNRedeemScript) != testRedeemScript {
		t.Error("M-of-N redeem script different from expected script.")
	}
}

func TestCheckPublicKeyIsValid(t *testing.T) {
	invalidPublicKeyStrings := []string{
		"", //empty key
		"0446f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695c",   //wrong length key
		"0346f1c8de232a065da428bf76e44b41f59a46620dec0aedfc9b5ab651e91f2051d610fddc78b8eba38a634bfe9a74bb015a88c52b9b844c74997035e08a695ce9", //wrong prefix key
	}
	for _, publicKeyString := range invalidPublicKeyStrings {
		publicKey, _ := hex.DecodeString(publicKeyString)
		if CheckPublicKeyIsValid(publicKey) == nil {
			t.Error("CheckPublicKeyIsValid accepting invalids public keys as valid.")
		}
	}
}

func TestNewP2SHScriptPubKey(t *testing.T) {
	testRedeemScriptHashString := "51d9ac622c2133ca4aaf58d4a4239526eb42c348"
	testScriptPubKeyHex := "a91451d9ac622c2133ca4aaf58d4a4239526eb42c34887"

	redeemScriptHash, _ := hex.DecodeString(testRedeemScriptHashString)
	scriptPubKey, err := NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		t.Error(err)
	}
	scriptPubKeyHex := hex.EncodeToString(scriptPubKey)
	if scriptPubKeyHex != testScriptPubKeyHex {
		t.Error("P2SH scriptPubKey different from expected script.")
	}
}

func TestNewP2PKHScriptPubKey(t *testing.T) {
	testPublicAddressString := "13LSqJeZBpqLHzmLkJ5mvRHiM11waShFUP"
	testPublicKeyHash := base58check.Decode(testPublicAddressString)
	testScriptPubKeyHex := "76a914199db810a3c8ae5e55c0432d2b72e55b0634f79088ac"

	scriptPubKey, err := NewP2PKHScriptPubKey(testPublicKeyHash)
	if err != nil {
		t.Error(err)
	}
	scriptPubKeyHex := hex.EncodeToString(scriptPubKey)
	if scriptPubKeyHex != testScriptPubKeyHex {
		t.Error("P2PKH scriptPubKey different from expected script.")
	}
}

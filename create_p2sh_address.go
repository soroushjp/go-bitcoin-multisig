package main

import (
	"encoding/hex"
	"fmt"
	"github.com/soroushjp/hellobitcoin/base58check"
	"github.com/soroushjp/hellobitcoin/btcutils"
	"log"
)

func main() {

	//Temporary generate two public keys. This should be a flag for users to give public keys in hex format
	privateKey1 := btcutils.GeneratePrivateKey()
	privateKey2 := btcutils.GeneratePrivateKey()
	publicKey1 := btcutils.GeneratePublicKey(privateKey1)
	publicKey2 := btcutils.GeneratePublicKey(privateKey2)
	publicKeyHex1 := hex.EncodeToString(publicKey1)
	publicKeyHex2 := hex.EncodeToString(publicKey2)

	//Assume user has given us publicKeyHex1 and publicKeyHex2 as arguments

	publicKeyBytes1, err := hex.DecodeString(publicKeyHex1)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyBytes2, err := hex.DecodeString(publicKeyHex2)
	if err != nil {
		log.Fatal(err)
	}
	redeemScript := btcutils.CreateTwoOfTwoRedeemScript(publicKeyBytes1, publicKeyBytes2)
	redeemScriptHash, err := btcutils.Hash160(redeemScript)
	if err != nil {
		log.Fatal(err)
	}

	P2SHAddress := base58check.Encode("05", redeemScriptHash)

	fmt.Println("---------------------")
	fmt.Println("Your *P2SH ADDRESS* is:", "\n")
	fmt.Println(P2SHAddress, "\n")
	fmt.Println("Give this to sender funding multisig address with Bitcoin.")
	fmt.Println("---------------------", "\n")
	fmt.Println("---------------------")
	fmt.Println("Your *REDEEMSCRIPT* is:", "\n")
	fmt.Println(hex.EncodeToString(redeemScript), "\n")
	fmt.Println("Keep private and provide this to redeem multisig balance later.")
	fmt.Println("---------------------")
}

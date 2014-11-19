package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"fmt"
	"log"
)

func main() {

	//Temporary generate two public keys. This should be an input argument for users to give public keys in hex format
	privateKey1 := btcutils.NewPrivateKey()
	privateKey2 := btcutils.NewPrivateKey()
	publicKey1, _ := btcutils.NewPublicKey(privateKey1)
	publicKey2, _ := btcutils.NewPublicKey(privateKey2)
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
	redeemScript := btcutils.NewTwoOfTwoRedeemScript(publicKeyBytes1, publicKeyBytes2)
	redeemScriptHash, err := btcutils.Hash160(redeemScript)
	if err != nil {
		log.Fatal(err)
	}

	P2SHAddress := base58check.Encode("05", redeemScriptHash)

	fmt.Println("---------------------")
	fmt.Println("Your *P2SH ADDRESS* is:")
	fmt.Println(P2SHAddress)
	fmt.Println("Give this to sender funding multisig address with Bitcoin.")
	fmt.Println("---------------------")
	fmt.Println("---------------------")
	fmt.Println("Your *FIRST PRIVATE KEY* is:")
	fmt.Println(base58check.Encode("80", privateKey1))
	fmt.Println("Keep private and provide this to redeem multisig balance later.")
	fmt.Println("---------------------")
	fmt.Println("---------------------")
	fmt.Println("Your *SECOND PRIVATE KEY* is:")
	fmt.Println(base58check.Encode("80", privateKey2))
	fmt.Println("Keep private and provide this to redeem multisig balance later.")
	fmt.Println("---------------------")
	fmt.Println("---------------------")
	fmt.Println("Your *REDEEMSCRIPT* is:")
	fmt.Println(hex.EncodeToString(redeemScript))
	fmt.Println("Keep private and provide this to redeem multisig balance later.")
	fmt.Println("---------------------")
}

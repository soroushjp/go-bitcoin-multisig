package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"fmt"
	"log"
)

func main() {

	//Generate private key
	privateKey := btcutils.NewPrivateKey()
	//Generate public key from private key
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	//Get hex encoded version of public key
	publicKeyHex := hex.EncodeToString(publicKey)
	//Get public address by hashing with SHA256 and RIPEMD160 and base58 encoding with mainnet prefix 00
	publicKeyHash, err := btcutils.Hash160(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	publicAddress := base58check.Encode("00", publicKeyHash)
	//Get private key in Wallet Import Format (WIF) by base58 encoding with prefix 80
	privateKeyWIF := base58check.Encode("80", privateKey)
	//Output private key in WIF format, public key as hex and P2PKH public address
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("THESE KEY PAIRS ARE PSEUDORANDOM. FOR DEMONSTRATION PURPOSES ONLY.")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("Your private key is: (Keep private)")
	fmt.Println(privateKeyWIF, "\n")
	fmt.Println("Your public key is: (Required to generate multisig destination address)")
	fmt.Println(publicKeyHex, "\n")
	fmt.Println("Your public destination address is: (Required for standard wallet to wallet P2PKH transactions)")
	fmt.Println(publicAddress, "\n")
}

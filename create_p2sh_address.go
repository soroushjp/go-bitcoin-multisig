package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/soroushjp/hellobitcoin/base58check"
	secp256k1 "github.com/toxeus/go-secp256k1"
	"log"
	"math"
	"math/rand"
	"time"
)

func main() {

	//Temporary generate two public keys. This should be a flag for users to give public keys in hex format
	privateKey1 := generatePrivateKey()
	privateKey2 := generatePrivateKey()
	publicKey1 := generatePublicKey(privateKey1)
	publicKey2 := generatePublicKey(privateKey2)
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
	redeemScript := createTwoOfTwoRedeemScript(publicKeyBytes1, publicKeyBytes2)
	redeemScriptHash, err := hash160(redeemScript)
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

func generatePrivateKey() []byte {
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
		// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func generatePublicKey(privateKeyBytes []byte) []byte {
	//Generate the public key from the private key.
	//Unfortunately golang ecdsa package does not include a
	//secp256k1 curve as this is fairly specific to bitcoin
	//as I understand it, so I have used this one by toxeus which wraps the official bitcoin/c-secp256k1 with cgo.
	var privateKeyBytes32 [32]byte
	for i := 0; i < 32; i++ {
		privateKeyBytes32[i] = privateKeyBytes[i]
	}
	secp256k1.Start()
	publicKeyBytes, success := secp256k1.Pubkey_create(privateKeyBytes32, false)
	if !success {
		log.Fatal("Failed to create public key.")
	}

	secp256k1.Stop()

	return publicKeyBytes

}

func randInt(min int, max int) uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + rand.Intn(max-min))
}

func createTwoOfTwoRedeemScript(firstPublicKey []byte, secondPublicKey []byte) []byte {
	//<OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> OP_CHECKMULTISIG

	var redeemScript bytes.Buffer
	redeemScript.WriteByte(byte(82))                  //OP_2
	redeemScript.WriteByte(byte(len(firstPublicKey))) //PUSH
	redeemScript.Write(firstPublicKey)
	redeemScript.WriteByte(byte(len(secondPublicKey))) //PUSH
	redeemScript.Write(secondPublicKey)
	redeemScript.WriteByte(byte(82))  //OP_2
	redeemScript.WriteByte(byte(174)) //OP_CHECKMULTISIG
	return redeemScript.Bytes()

}

func hash160(hashBytes []byte) ([]byte, error) {
	//Does identical function to Script OP_HASH160. Hash once with SHA-256, then RIPEMD-160

	if hashBytes == nil {
		return nil, errors.New("Empty bytes cannot be hashed")
	}
	shaHash := sha256.New()
	shaHash.Write(hashBytes)
	var hash []byte = shaHash.Sum(nil) //SHA256 first
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(hash)
	hash = ripemd160Hash.Sum(nil) //RIPEMD160 second

	return hash, nil
}

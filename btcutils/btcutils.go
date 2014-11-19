package btcutils

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/sha256"
	"errors"
	secp256k1 "github.com/toxeus/go-secp256k1"
	"log"
	"math"
	"math/rand"
	"time"
)

func randInt(min int, max int) uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + rand.Intn(max-min))
}

func GeneratePrivateKey() []byte {
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
		// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
		// FOR DEMONSTRATION PURPOSES ONLY
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func GeneratePublicKey(privateKeyBytes []byte) []byte {
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

func CreateTwoOfTwoRedeemScript(firstPublicKey []byte, secondPublicKey []byte) []byte {
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

func Hash160(hashBytes []byte) ([]byte, error) {
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

package btcutils

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log"
	"math"
	"math/rand"
	"time"

	"code.google.com/p/go.crypto/ripemd160"
	secp256k1 "github.com/toxeus/go-secp256k1"
)

func randInt(min int, max int) uint8 {
	//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
	// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
	// FOR DEMONSTRATION PURPOSES ONLY
	rand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + rand.Intn(max-min))
}

func GenerateNonce() [32]byte {
	var bytes [32]byte
	for i := 0; i < 32; i++ {
		//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
		// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
		// FOR DEMONSTRATION PURPOSES ONLY
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
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

func CreateP2SHScriptPubKey(redeemScriptHash []byte) ([]byte, error) {
	if redeemScriptHash == nil {
		return nil, errors.New("redeemScriptHash can't be empty")
	}
	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(169))                   //OP_HASH160
	scriptPubKey.WriteByte(byte(len(redeemScriptHash))) //PUSH
	scriptPubKey.Write(redeemScriptHash)
	scriptPubKey.WriteByte(byte(135)) //OP_EQUAL

	return scriptPubKey.Bytes(), nil
}

func CreateP2PKHScriptPubKey(publicKeyBytes []byte) []byte {
	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(118))                 //OP_DUP
	scriptPubKey.WriteByte(byte(169))                 //OP_HASH160
	scriptPubKey.WriteByte(byte(len(publicKeyBytes))) //PUSH
	scriptPubKey.Write(publicKeyBytes)
	scriptPubKey.WriteByte(byte(136)) //OP_EQUALVERIFY
	scriptPubKey.WriteByte(byte(172)) //OP_CHECKSIG

	return scriptPubKey.Bytes()
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

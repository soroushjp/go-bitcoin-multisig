package btcutils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

func newNonce() [32]byte {
	var bytes [32]byte
	for i := 0; i < 32; i++ {
		//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
		// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
		// FOR DEMONSTRATION PURPOSES ONLY
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func NewPrivateKey() []byte {
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		//THIS IS *NOT* "cryptographically random" AND IS *NOT* SECURE.
		// PLEASE USE BETTER SOURCE OF RANDOMNESS IN PRODUCTION SYSTEMS
		// FOR DEMONSTRATION PURPOSES ONLY
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func NewPublicKey(privateKeyBytes []byte) ([]byte, error) {
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
		return nil, errors.New("Failed to create public key from provided private key bytes.")
	}
	secp256k1.Stop()

	return publicKeyBytes, nil

}

func NewTwoOfTwoRedeemScript(firstPublicKey []byte, secondPublicKey []byte) []byte {
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

func NewP2SHScriptPubKey(redeemScriptHash []byte) ([]byte, error) {
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

func NewP2PKHScriptPubKey(publicKeyHashBytes []byte) []byte {
	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(118))                     //OP_DUP
	scriptPubKey.WriteByte(byte(169))                     //OP_HASH160
	scriptPubKey.WriteByte(byte(len(publicKeyHashBytes))) //PUSH
	scriptPubKey.Write(publicKeyHashBytes)
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

func NewRawTransaction(inputTransactionHash string, satoshis int, scriptSig []byte, scriptPubKey []byte) ([]byte, error) {
	//Create the raw transaction.

	//Version field
	version, err := hex.DecodeString("01000000")
	if err != nil {
		return nil, err
	}
	//# of inputs (always 1 in our case)
	inputs, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	//Input transaction hash
	inputTransactionBytes, err := hex.DecodeString(inputTransactionHash)
	if err != nil {
		return nil, err
	}
	//Convert input transaction hash to little-endian form
	inputTransactionBytesReversed := make([]byte, len(inputTransactionBytes))
	for i := 0; i < len(inputTransactionBytes); i++ {
		inputTransactionBytesReversed[i] = inputTransactionBytes[len(inputTransactionBytes)-i-1]
	}
	//Ouput index of input transaction
	outputIndex, err := hex.DecodeString("00000000")
	if err != nil {
		return nil, err
	}
	//scriptSig length. To allow scriptSig > 255 bytes, we use variable length integer syntax from protocol spec
	var scriptSigLengthBytes []byte
	if len(scriptSig) < 253 {
		scriptSigLengthBytes = []byte{byte(len(scriptSig))}
	} else {
		scriptSigLengthBytes = make([]byte, 3)
		binary.LittleEndian.PutUint16(scriptSigLengthBytes, uint16(len(scriptSig)))
		copy(scriptSigLengthBytes[1:3], scriptSigLengthBytes[0:2])
		scriptSigLengthBytes[0] = 253 //Signifies that next two bytes are 2-byte representation of scriptSig length

	}
	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		return nil, err
	}
	//Numbers of outputs for the transaction being created. Always one in this example.
	numOutputs, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	//Satoshis to send.
	satoshiBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes, uint64(satoshis))
	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(inputs)
	buffer.Write(inputTransactionBytesReversed)
	buffer.Write(outputIndex)
	buffer.Write(scriptSigLengthBytes)
	buffer.Write(scriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	buffer.Write(satoshiBytes)
	buffer.WriteByte(byte(len(scriptPubKey)))
	buffer.Write(scriptPubKey)
	buffer.Write(lockTimeField)

	return buffer.Bytes(), nil
}

func NewSignature(rawTransaction []byte, privateKeyBytes []byte) ([]byte, error) {

	secp256k1.Start()
	var privateKeyBytes32 [32]byte
	for i := 0; i < 32; i++ {
		privateKeyBytes32[i] = privateKeyBytes[i]
	}

	//Get the raw public key
	publicKeyBytes, success := secp256k1.Pubkey_create(privateKeyBytes32, false)
	if !success {
		return nil, errors.New("Failed to convert private key to public key")
	}

	//Hash the raw transaction twice before the signing
	shaHash := sha256.New()
	shaHash.Write(rawTransaction)
	var hash []byte = shaHash.Sum(nil)

	shaHash2 := sha256.New()
	shaHash2.Write(hash)
	rawTransactionHashed := shaHash2.Sum(nil)

	//Sign the raw transaction
	signedTransaction, success := secp256k1.Sign(rawTransactionHashed, privateKeyBytes32, newNonce())
	if !success {
		return nil, errors.New("Failed to sign transaction")
	}

	//Verify that it worked.
	verified := secp256k1.Verify(rawTransactionHashed, signedTransaction, publicKeyBytes)
	if !verified {
		return nil, errors.New("Failed to verify signed transaction")
	}

	secp256k1.Stop()

	return signedTransaction, nil
}

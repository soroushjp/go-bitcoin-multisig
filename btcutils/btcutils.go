// Package btcutils contains a number of useful Bitcoin related functions originally used in the go-bitcoin-multisig
// project but useful in any general Bitcoin project.
package btcutils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"time"

	"code.google.com/p/go.crypto/ripemd160"
	secp256k1 "github.com/toxeus/go-secp256k1"
)

// setFixedNonce is used for testing and debugging. It is by default false, but if set to true, then newNonce()
// will always return a zero-valued [32]byte{}. Allows repeatable ECDSA signatures for testing
// **Should never be turned on in production. Limit to use in tests only.**
var SetFixedNonce bool

//Fixed nonce value for repeatable testing.
//We declare var and not const because Go slices are mutable and cannot be const, but we use fixedNonce like a constant.
var FIXED_NONCE = [...]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

func randInt(min int, max int) uint8 {
	//This function is *not* cryptographically secure.
	//Used for nonce which does not need to be cryptographically secure, just changing with each signature
	mathrand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + mathrand.Intn(max-min))
}

func newNonce() [32]byte {
	//This function is *not* cryptographically secure.
	//Used for nonce which does not need to be cryptographically secure, just changing with each signature
	var bytes [32]byte
	if !SetFixedNonce {
		for i := 0; i < 32; i++ {
			bytes[i] = byte(randInt(0, math.MaxUint8))
		}
	} else {
		bytes = FIXED_NONCE
	}
	return bytes
}

// NewRandomBytes generates pseudorandom bytes of length size.
// Cryptographically secure to the limits of crypto/rand package.
func NewRandomBytes(size int) ([]byte, error) {
	randBytes := make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

// NewPrivateKey generates a pseudorandom private key compatible with ECDSA.
// Cryptographically secure to the limits of crypto/rand package.
func NewPrivateKey() []byte {
	bytes, err := NewRandomBytes(32)
	if err != nil {
		log.Fatal(err)
		//Throw an error instead of just returning one quietly since cryptographically secure pseudorandomness is crucial to private key.
	}
	return bytes
}

// NewPublicKey generates the public key from the private key.
// Unfortunately golang ecdsa package does not include a
// secp256k1 curve as this is fairly specific to Bitcoin.
// Using toxeus/go-secp256k1 which wraps the official bitcoin/c-secp256k1 with cgo.
func NewPublicKey(privateKey []byte) ([]byte, error) {
	var privateKey32 [32]byte
	for i := 0; i < 32; i++ {
		privateKey32[i] = privateKey[i]
	}
	secp256k1.Start()
	publicKey, success := secp256k1.Pubkey_create(privateKey32, false)
	if !success {
		return nil, errors.New("Failed to create public key from provided private key.")
	}
	secp256k1.Stop()
	return publicKey, nil
}

// Hash160 performs the same operations as OP_HASH160 in Bitcoin Script
// It hashes the given data first with SHA256, then RIPEMD160
func Hash160(data []byte) ([]byte, error) {
	//Does identical function to Script OP_HASH160. Hash once with SHA-256, then RIPEMD-160
	if data == nil {
		return nil, errors.New("Empty bytes cannot be hashed")
	}
	shaHash := sha256.New()
	shaHash.Write(data)
	hash := shaHash.Sum(nil) //SHA256 first
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(hash)
	hash = ripemd160Hash.Sum(nil) //RIPEMD160 second

	return hash, nil
}

// NewMOfNRedeemScript creates a M-of-N Multisig redeem script given m, n and n public keys
func NewMOfNRedeemScript(m int, n int, publicKeys [][]byte) ([]byte, error) {
	//Check we have valid numbers for M and N
	if n < 1 || n > 7 {
		return nil, errors.New("N must be between 1 and 7 (inclusive) for valid, standard P2SH multisig transaction as per Bitcoin protocol.")
	}
	if m < 1 || m > n {
		return nil, errors.New("M must be between 1 and N (inclusive).")
	}
	//Check we have N public keys as necessary.
	if len(publicKeys) != n {
		return nil, errors.New(fmt.Sprintf("Need exactly %d public keys to create P2SH address for %d-of-%d multisig transaction. Only %d keys provided.", n, m, n, len(publicKeys)))
	}
	//Get OP Code for m and n.
	//81 is OP_1, 82 is OP_2 etc.
	//80 is not a valid OP_Code, so we floor at 81
	mOPCode := OP_1 + (m - 1)
	nOPCode := OP_1 + (n - 1)
	//Multisig redeemScript format:
	//<OP_m> <A pubkey> <B pubkey> <C pubkey>... <OP_n> OP_CHECKMULTISIG
	var redeemScript bytes.Buffer
	redeemScript.WriteByte(byte(mOPCode)) //m
	for _, publicKey := range publicKeys {
		err := CheckPublicKeyIsValid(publicKey)
		if err != nil {
			return nil, err
		}
		redeemScript.WriteByte(byte(len(publicKey))) //PUSH
		redeemScript.Write(publicKey)                //<pubkey>
	}
	redeemScript.WriteByte(byte(nOPCode)) //n
	redeemScript.WriteByte(byte(OP_CHECKMULTISIG))
	return redeemScript.Bytes(), nil
}

// CheckPublicKeyIsValid runs a couple of checks to make sure a public key looks valid.
// Returns an error with a helpful message or nil if key is valid.
func CheckPublicKeyIsValid(publicKey []byte) error {
	errMessage := ""
	if publicKey == nil {
		errMessage += "Public key cannot be empty.\n"
	} else if len(publicKey) != 65 {
		errMessage += fmt.Sprintf("Public key should be 65 bytes long. Provided public key is %d bytes long.", len(publicKey))
	} else if publicKey[0] != byte(4) {
		errMessage += fmt.Sprintf("Public key first byte should be 0x04. Provided public key first byte is 0x%v.", hex.EncodeToString([]byte{publicKey[0]}))
	}
	if errMessage != "" {
		errMessage += "Invalid public key:\n"
		errMessage += hex.EncodeToString(publicKey)
		return errors.New(errMessage)
	}
	return nil
}

// NewP2SHScriptPubKey creates a scriptPubKey for a P2SH transaction given the redeemScript hash
func NewP2SHScriptPubKey(redeemScriptHash []byte) ([]byte, error) {
	if redeemScriptHash == nil {
		return nil, errors.New("redeemScriptHash can't be empty.")
	}
	//P2SH scriptSig format:
	//<OP_HASH160> <Hash160(redeemScript)> <OP_EQUAL>
	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(OP_HASH160))
	scriptPubKey.WriteByte(byte(len(redeemScriptHash))) //PUSH
	scriptPubKey.Write(redeemScriptHash)
	scriptPubKey.WriteByte(byte(OP_EQUAL))
	return scriptPubKey.Bytes(), nil
}

// NewP2PKHScriptPubKey creates a scriptPubKey for a P2PKH transaction given the destination public key hash
func NewP2PKHScriptPubKey(publicKeyHash []byte) ([]byte, error) {
	if publicKeyHash == nil {
		return nil, errors.New("publicKeyHash can't be empty.")
	}
	//P2PKH scriptSig format:
	//<OP_DUP> <OP_HASH160> <pubKeyHash> <OP_EQUALVERIFY> <OP_CHECKSIG>
	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(OP_DUP))
	scriptPubKey.WriteByte(byte(OP_HASH160))
	scriptPubKey.WriteByte(byte(len(publicKeyHash))) //PUSH
	scriptPubKey.Write(publicKeyHash)
	scriptPubKey.WriteByte(byte(OP_EQUALVERIFY))
	scriptPubKey.WriteByte(byte(OP_CHECKSIG))
	return scriptPubKey.Bytes(), nil
}

// NewRawTransaction creates a Bitcoin transaction given inputs, output satoshi amount, scriptSig and scriptPubKey
func NewRawTransaction(inputTxHash string, satoshis int, scriptSig []byte, scriptPubKey []byte) ([]byte, error) {
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
	inputTxBytes, err := hex.DecodeString(inputTxHash)
	if err != nil {
		return nil, err
	}
	//Convert input transaction hash to little-endian form
	inputTxBytesReversed := make([]byte, len(inputTxBytes))
	for i := 0; i < len(inputTxBytes); i++ {
		inputTxBytesReversed[i] = inputTxBytes[len(inputTxBytes)-i-1]
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
	buffer.Write(inputTxBytesReversed)
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

// NewSignature generates a ECDSA signature given the raw transaction and privateKey to sign with
func NewSignature(rawTransaction []byte, privateKey []byte) ([]byte, error) {
	//Start secp256k1
	secp256k1.Start()
	var privateKey32 [32]byte
	for i := 0; i < 32; i++ {
		privateKey32[i] = privateKey[i]
	}
	//Get the raw public key
	publicKey, success := secp256k1.Pubkey_create(privateKey32, false)
	if !success {
		return nil, errors.New("Failed to create public key from provided private key.")
	}
	//Hash the raw transaction twice with SHA256 before the signing
	shaHash := sha256.New()
	shaHash.Write(rawTransaction)
	var hash []byte = shaHash.Sum(nil)
	shaHash2 := sha256.New()
	shaHash2.Write(hash)
	rawTransactionHashed := shaHash2.Sum(nil)
	//Sign the raw transaction
	signedTransaction, success := secp256k1.Sign(rawTransactionHashed, privateKey32, newNonce())
	if !success {
		return nil, errors.New("Failed to sign transaction")
	}
	//Verify that it worked.
	verified := secp256k1.Verify(rawTransactionHashed, signedTransaction, publicKey)
	if !verified {
		return nil, errors.New("Failed to verify signed transaction")
	}
	//Stop secp256k1 and return signature
	secp256k1.Stop()
	return signedTransaction, nil
}

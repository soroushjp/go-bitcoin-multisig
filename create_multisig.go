package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"time"

	"code.google.com/p/go.crypto/ripemd160"
	secp256k1 "github.com/toxeus/go-secp256k1"
)

var flagPrivateKey string
var flagPublicKey string
var flagInputTransaction string
var flagSatoshis int

var privateKey1 []byte
var privateKey2 []byte
var publicKey1 []byte
var publicKey2 []byte

var scriptPubKey []byte

func main() {
	//This transaction code is not completely robust.
	//It expects that you have exactly 1 input transaction, and 1 output address.
	//It also expects that your transaction is a standard Pay To Public Key Hash (P2PKH) transaction.
	//This is the most common form used to send a transaction to one or multiple Bitcoin addresses.

	//Parse flags
	flag.StringVar(&flagPrivateKey, "private-key", "", "Private key of bitcoin to send.")
	flag.StringVar(&flagPublicKey, "public-key", "", "Public address of bitcoin to send.")
	flag.StringVar(&flagInputTransaction, "input-transaction", "", "Input transaction hash of bitcoin to send.")
	flag.IntVar(&flagSatoshis, "satoshis", 0, "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).")
	flag.Parse()

	privateKey1 = generatePrivateKey()
	privateKey2 = generatePrivateKey()
	publicKey1 = generatePublicKey(privateKey1)
	publicKey2 = generatePublicKey(privateKey2)

	privateKeyWif1 := base58CheckEncode("80", privateKey1)
	privateKeyWif2 := base58CheckEncode("80", privateKey2)

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	tempScriptSig := createP2PKHScriptPubKey(flagPublicKey)

	//2 of 2 Redeem Script
	twoOfTwoRedeemScript := createTwoOfTwoRedeemScript(publicKey1, publicKey2)

	//Script pub key
	scriptPubKey = createP2SHScriptPubKey(twoOfTwoRedeemScript)

	rawTransaction := createRawTransaction(flagInputTransaction, flagSatoshis, tempScriptSig, scriptPubKey)

	//After completing the raw transaction, we append
	//SIGHASH_ALL in little-endian format to the end of the raw transaction.
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		log.Fatal(err)
	}

	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()

	//Sign the raw transaction, and output it to the console.
	finalTransaction := signRawTransaction(rawTransactionWithHashCodeType, flagPrivateKey)
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	fmt.Println("Your first generated private key for multisig is")
	fmt.Println(privateKeyWif1)
	fmt.Println("Your second generated private key for multisig is")
	fmt.Println(privateKeyWif2)
	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func createP2PKHScriptPubKey(publicKeyBase58 string) []byte {
	publicKeyBytes := base58CheckDecode(publicKeyBase58)

	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(118))                 //OP_DUP
	scriptPubKey.WriteByte(byte(169))                 //OP_HASH160
	scriptPubKey.WriteByte(byte(len(publicKeyBytes))) //PUSH
	scriptPubKey.Write(publicKeyBytes)
	scriptPubKey.WriteByte(byte(136)) //OP_EQUALVERIFY
	scriptPubKey.WriteByte(byte(172)) //OP_CHECKSIG
	return scriptPubKey.Bytes()
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

func createP2SHScriptPubKey(redeemScript []byte) []byte {

	if redeemScript == nil {
		return nil
	}

	//We need to perform SHA256 and then RIPEMD-160 to get Hash160(redeemScript) as required by P2SH
	shaHash := sha256.New()
	shaHash.Write(redeemScript)
	var redeemScriptHash []byte = shaHash.Sum(nil) //SHA256 first
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(redeemScriptHash)
	redeemScriptHash = ripemd160Hash.Sum(nil) //RIPEMD160 second

	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(169))                   //OP_HASH160
	scriptPubKey.WriteByte(byte(len(redeemScriptHash))) //PUSH
	scriptPubKey.Write(redeemScriptHash)
	scriptPubKey.WriteByte(byte(135)) //OP_EQUAL

	return scriptPubKey.Bytes()
}

func signRawTransaction(rawTransaction []byte, privateKeyBase58 string) []byte {
	//Here we start the process of signing the raw transaction.

	secp256k1.Start()
	privateKeyBytes := base58CheckDecode(privateKeyBase58)
	var privateKeyBytes32 [32]byte

	for i := 0; i < 32; i++ {
		privateKeyBytes32[i] = privateKeyBytes[i]
	}

	//Get the raw public key
	publicKeyBytes, success := secp256k1.Pubkey_create(privateKeyBytes32, false)
	if !success {
		log.Fatal("Failed to convert private key to public key")
	}

	//Hash the raw transaction twice before the signing
	shaHash := sha256.New()
	shaHash.Write(rawTransaction)
	var hash []byte = shaHash.Sum(nil)

	shaHash2 := sha256.New()
	shaHash2.Write(hash)
	rawTransactionHashed := shaHash2.Sum(nil)

	//Sign the raw transaction
	signedTransaction, success := secp256k1.Sign(rawTransactionHashed, privateKeyBytes32, generateNonce())
	if !success {
		log.Fatal("Failed to sign transaction")
	}

	//Verify that it worked.
	verified := secp256k1.Verify(rawTransactionHashed, signedTransaction, publicKeyBytes)
	if !verified {
		log.Fatal("Failed to sign transaction")
	}

	secp256k1.Stop()

	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	//+1 for hashCodeType
	signedTransactionLength := byte(len(signedTransaction) + 1)

	var publicKeyBuffer bytes.Buffer
	publicKeyBuffer.Write(publicKeyBytes)
	pubKeyLength := byte(len(publicKeyBuffer.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signedTransactionLength)
	buffer.Write(signedTransaction)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(publicKeyBuffer.Bytes())

	scriptSig := buffer.Bytes()

	//Return the final transaction
	return createRawTransaction(flagInputTransaction, flagSatoshis, scriptSig, scriptPubKey)
}

func generateNonce() [32]byte {
	var bytes [32]byte
	for i := 0; i < 32; i++ {
		//This is not "cryptographically random"
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func createRawTransaction(inputTransactionHash string, satoshis int, scriptSig []byte, scriptPubKey []byte) []byte {
	//Create the raw transaction.

	//Version field
	version, err := hex.DecodeString("01000000")
	if err != nil {
		log.Fatal(err)
	}

	//# of inputs (always 1 in our case)
	inputs, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	//Input transaction hash
	inputTransactionBytes, err := hex.DecodeString(inputTransactionHash)
	if err != nil {
		log.Fatal(err)
	}

	//Convert input transaction hash to little-endian form
	inputTransactionBytesReversed := make([]byte, len(inputTransactionBytes))
	for i := 0; i < len(inputTransactionBytes); i++ {
		inputTransactionBytesReversed[i] = inputTransactionBytes[len(inputTransactionBytes)-i-1]
	}

	//Ouput index of input transaction
	outputIndex, err := hex.DecodeString("00000000")
	if err != nil {
		log.Fatal(err)
	}

	//Script sig length
	scriptSigLength := len(scriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		log.Fatal(err)
	}

	//Numbers of outputs for the transaction being created. Always one in this example.
	numOutputs, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	//Satoshis to send.
	satoshiBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes, uint64(satoshis))

	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		log.Fatal(err)
	}

	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(inputs)
	buffer.Write(inputTransactionBytesReversed)
	buffer.Write(outputIndex)
	buffer.WriteByte(byte(scriptSigLength))
	buffer.Write(scriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	buffer.Write(satoshiBytes)
	buffer.WriteByte(byte(len(scriptPubKey)))
	buffer.Write(scriptPubKey)
	buffer.Write(lockTimeField)

	return buffer.Bytes()
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

func generatePublicKeyHash(publicKeyBytes []byte) []byte {
	//Next we get a sha256 hash of the public key generated
	//via ECDSA, and then get a ripemd160 hash of the sha256 hash.
	shaHash := sha256.New()
	shaHash.Write(publicKeyBytes)
	shadPublicKeyBytes := shaHash.Sum(nil)

	ripeHash := ripemd160.New()
	ripeHash.Write(shadPublicKeyBytes)
	ripeHashedBytes := ripeHash.Sum(nil)

	return ripeHashedBytes
}

func generatePrivateKey() []byte {
	bytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		//This is not "cryptographically random"
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func randInt(min int, max int) uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + rand.Intn(max-min))
}

package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

var flagPrivateKey1 string
var flagPrivateKey2 string
var flagDestination string
var flagInputTransaction string
var flagRedeemScript string
var flagSatoshis int

var scriptPubKey []byte

func main() {
	//Parse flags
	flag.StringVar(&flagPrivateKey1, "private-key1", "", "Private key of multisig signature 1.")
	flag.StringVar(&flagPrivateKey2, "private-key2", "", "Private key of multisig signature 2.")
	flag.StringVar(&flagDestination, "destination", "", "Public destination address to send bitcoins.")
	flag.StringVar(&flagRedeemScript, "redeemScript", "", "Hex representation of redeem script that matches redeem script in P2SH input transaction.")
	flag.StringVar(&flagInputTransaction, "input-transaction", "", "Input transaction hash of bitcoin to send.")
	flag.IntVar(&flagSatoshis, "satoshis", 0, "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).")
	flag.Parse()

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the redeemScript of the input P2SH transaction.

	redeemScript, err := hex.DecodeString(flagRedeemScript)
	if err != nil {
		log.Fatal(err)
	}
	//Get private key as decoded raw bytes
	privateKey1 := base58check.Decode(flagPrivateKey1)
	privateKey2 := base58check.Decode(flagPrivateKey2)
	//Create scriptPubKey with provided destination public key
	publicKeyHash := base58check.Decode(flagDestination)
	scriptPubKey = btcutils.NewP2PKHScriptPubKey(publicKeyHash)
	//Create unsigned raw transaction
	//scriptSig in unsigned transaction is serialized redeemScript of input P2SH transaction.
	rawTransaction, err := btcutils.NewRawTransaction(flagInputTransaction, flagSatoshis, redeemScript, scriptPubKey)
	if err != nil {
		log.Fatal(err)
	}
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
	finalTransaction, err := signRawTransaction(rawTransactionWithHashCodeType, privateKey1, privateKey2, redeemScript)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func signRawTransaction(rawTransaction []byte, firstPrivateKey []byte, secondPrivateKey []byte, redeemScript []byte) ([]byte, error) {
	firstSignature, err := btcutils.NewSignature(rawTransaction, firstPrivateKey)
	if err != nil {
		return nil, err
	}
	secondSignature, err := btcutils.NewSignature(rawTransaction, secondPrivateKey)
	if err != nil {
		return nil, err
	}
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}

	//+1 for hashCodeType
	firstSignatureLength := byte(len(firstSignature) + 1)
	secondSignatureLength := byte(len(secondSignature) + 1)

	var buffer bytes.Buffer
	buffer.WriteByte(byte(0))                 //OP_0 for Multisig off-by-one error
	buffer.WriteByte(firstSignatureLength)    //PUSH first signature
	buffer.Write(firstSignature)              // First signature
	buffer.WriteByte(hashCodeType[0])         //hash type SIGHASH_ALL
	buffer.WriteByte(secondSignatureLength)   //PUSH second signature
	buffer.Write(secondSignature)             // Second signature
	buffer.WriteByte(hashCodeType[0])         //hash type SIGHASH_ALL
	buffer.WriteByte(byte(76))                //OP_76, since we are pushing >75 bytes to stack with redeemScript
	buffer.WriteByte(byte(len(redeemScript))) //PUSH redeemScript
	buffer.Write(redeemScript)                //redeemScript

	scriptSig := buffer.Bytes()

	signedRawTransaction, err := btcutils.NewRawTransaction(flagInputTransaction, flagSatoshis, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}

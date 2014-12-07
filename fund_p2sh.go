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

var flagPrivateKey string
var flagPublicAddress string
var flagInputTransaction string
var flagSatoshis int
var flagP2SHDestination string

func main() {
	//Parse flags
	flag.StringVar(&flagPrivateKey, "private-key", "", "Private key of bitcoin to send.")
	flag.StringVar(&flagPublicAddress, "public-address", "", "Public address of bitcoin to send.")
	flag.StringVar(&flagInputTransaction, "input-transaction", "", "Input transaction hash of bitcoin to send.")
	flag.IntVar(&flagSatoshis, "satoshis", 0, "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).")
	flag.StringVar(&flagP2SHDestination, "destination", "", "Destination address. For P2SH, this should start with '3'.")
	flag.Parse()

	//Get private key as decoded raw bytes
	privateKey := base58check.Decode(flagPrivateKey)
	//In order to construct the raw transaction we need the input transaction hash,
	//the P2SH destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	publicKeyHash := base58check.Decode(flagPublicAddress)
	tempScriptSig := btcutils.NewP2PKHScriptPubKey(publicKeyHash)

	redeemScriptHash := base58check.Decode(flagP2SHDestination)

	scriptPubKey, err := btcutils.NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		log.Fatal(err)
	}

	rawTransaction, err := btcutils.NewRawTransaction(flagInputTransaction, flagSatoshis, tempScriptSig, scriptPubKey)
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
	finalTransaction, err := signP2PKHTransaction(rawTransactionWithHashCodeType, privateKey, scriptPubKey)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func signP2PKHTransaction(rawTransaction []byte, privateKey []byte, scriptPubKey []byte) ([]byte, error) {
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	signature, err := btcutils.NewSignature(rawTransaction, privateKey)
	if err != nil {
		return nil, err
	}
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}

	//+1 for hashCodeType
	signatureLength := byte(len(signature) + 1)

	var publicKeyBuffer bytes.Buffer
	publicKeyBuffer.Write(publicKey)
	pubKeyLength := byte(len(publicKeyBuffer.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signatureLength)
	buffer.Write(signature)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(publicKeyBuffer.Bytes())

	scriptSig := buffer.Bytes()

	signedRawTransaction, err := btcutils.NewRawTransaction(flagInputTransaction, flagSatoshis, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}

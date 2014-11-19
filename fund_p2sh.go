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
var flagPublicKey string
var flagInputTransaction string
var flagSatoshis int
var flagP2SHDestination string

func main() {
	//Parse flags
	flag.StringVar(&flagPrivateKey, "private-key", "", "Private key of bitcoin to send.")
	flag.StringVar(&flagPublicKey, "public-key", "", "Public address of bitcoin to send.")
	flag.StringVar(&flagInputTransaction, "input-transaction", "", "Input transaction hash of bitcoin to send.")
	flag.IntVar(&flagSatoshis, "satoshis", 0, "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).")
	flag.StringVar(&flagP2SHDestination, "destination", "", "Destination address. For P2SH, this should start with '3'.")
	flag.Parse()

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	tempScriptSig := btcutils.NewP2PKHScriptPubKey(base58check.Decode(flagPublicKey))

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
	finalTransaction, err := signRawTransaction(rawTransactionWithHashCodeType, flagPrivateKey, scriptPubKey)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func signRawTransaction(rawTransaction []byte, privateKeyBase58 string, scriptPubKey []byte) ([]byte, error) {

	privateKeyBytes := base58check.Decode(privateKeyBase58)
	publicKeyBytes, err := btcutils.NewPublicKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	signature, err := btcutils.NewSignature(rawTransaction, privateKeyBytes)
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
	publicKeyBuffer.Write(publicKeyBytes)
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

package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"bytes"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
)

var flagPrivateKeys string
var flagDestination string
var flagInputTransaction string
var flagRedeemScript string
var flagSatoshis int

const REQUIRED_FLAG_COUNT = 5

var scriptPubKey []byte

func main() {
	//Parse flags
	flag.StringVar(&flagPrivateKeys, "private-keys", "", "Comma separated list of private keys to sign with. Whitespace is stripped and quotes may be placed around keys. Eg. key1,key2,\"key3\" .")
	flag.StringVar(&flagDestination, "destination", "", "Public destination address to send bitcoins.")
	flag.StringVar(&flagRedeemScript, "redeemScript", "", "Hex representation of redeem script that matches redeem script in P2SH input transaction.")
	flag.StringVar(&flagInputTransaction, "input-transaction", "", "Input transaction hash of bitcoin to send.")
	flag.IntVar(&flagSatoshis, "satoshis", 0, "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).")
	flag.Parse()
	if flag.NFlag() != REQUIRED_FLAG_COUNT {
		//We only need to check flag count because Go will automatically throw an error for undefined flags
		log.Fatal("Please provide all required flags.")
	}

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the redeemScript of the input P2SH transaction.

	//Convert redeemScript hex to raw bytes
	redeemScript, err := hex.DecodeString(flagRedeemScript)
	if err != nil {
		log.Fatal(err)
	}
	//Convert private-keys argument into slice of private key bytes with necessary tidying
	flagPrivateKeys = strings.Replace(flagPrivateKeys, "'", "\"", -1) //Replace single quotes with double since csv package only recognizes double quotes
	privateKeyStrings, err := csv.NewReader(strings.NewReader(flagPrivateKeys)).Read()
	if err != nil {
		log.Fatal(err)
	}
	privateKeys := make([][]byte, len(privateKeyStrings))
	for i, privateKeyString := range privateKeyStrings {
		privateKeyString = strings.TrimSpace(privateKeyString) //Trim whitespace
		if privateKeyString == "" {
			log.Fatal("Provided private key cannot be empty.")
		}
		privateKeys[i] = base58check.Decode(privateKeyString) //Get private keys as slice of raw bytes
	}
	//Create scriptPubKey with provided destination public key
	publicKeyHash := base58check.Decode(flagDestination)
	scriptPubKey, err = btcutils.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		log.Fatal(err)
	}
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
	//Sign the raw transaction
	finalTransaction, err := signMultisigTransaction(rawTransactionWithHashCodeType, privateKeys, redeemScript)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)
	//Output final transaction
	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func signMultisigTransaction(rawTransaction []byte, orderedPrivateKeys [][]byte, redeemScript []byte) ([]byte, error) {
	//Hash type SIGHASH_ALL
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	//Generate signatures for each provided key
	signatures := make([][]byte, len(orderedPrivateKeys))
	for i, privateKey := range orderedPrivateKeys {
		signatures[i], err = btcutils.NewSignature(rawTransaction, privateKey)
		if err != nil {
			return nil, err
		}
	}
	//Create scriptSig
	var buffer bytes.Buffer
	buffer.WriteByte(byte(0)) //OP_0 for Multisig off-by-one error
	for _, signature := range signatures {
		buffer.WriteByte(byte(len(signature) + 1)) //PUSH each signature. Add one for hash type byte
		buffer.Write(signature)                    // Signature bytes
		buffer.WriteByte(hashCodeType[0])          //hash type
	}
	buffer.WriteByte(byte(76))                //OP_76, since we are pushing >75 bytes to stack with redeemScript
	buffer.WriteByte(byte(len(redeemScript))) //PUSH redeemScript
	buffer.Write(redeemScript)                //redeemScript
	scriptSig := buffer.Bytes()
	//Finally create transaction with actual scriptSig
	signedRawTransaction, err := btcutils.NewRawTransaction(flagInputTransaction, flagSatoshis, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}

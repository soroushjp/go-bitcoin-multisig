// spend.go - Spending P2SH multisig funds to a Bitcoin address.
package multisig

import (
	"github.com/prettymuchbryce/hellobitcoin/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

//OutputSpend formats and prints relevant outputs to the user.
func OutputSpend(flagPrivateKeys string, flagDestination string, flagRedeemScript string, flagInputTx string, flagAmount int) {
	finalTransactionHex := generateSpend(flagPrivateKeys, flagDestination, flagRedeemScript, flagInputTx, flagAmount)
	//Output final transaction
	//Output our final transaction
	fmt.Printf(`
-----------------------------------------------------------------------------------------------------------------------------------
Your raw spending transaction is:
%v
Give this to the sender funding the multisig address with Bitcoin.
-----------------------------------------------------------------------------------------------------------------------------------
`,
		finalTransactionHex,
	)
}

// generateSpend is the high-level logic for spending from a P2SH multisig address with the 'go-bitcoin-multisig spend' subcommand.
// Takes flagPrivateKeys (comma separated list of M private keys), flagDestination (destination address of spent funds),
// flagRedeemScript (redeemScript that matches P2SH script), flagInputTx (input transaction hash of P2SH input to spend)
// and flagAmount (amount in Satoshis to send, with balance left over from input being used as transaction fee) as arguments.
func generateSpend(flagPrivateKeys string, flagDestination string, flagRedeemScript string, flagInputTx string, flagAmount int) string {
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
	scriptPubKey, err := btcutils.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		log.Fatal(err)
	}
	//Create unsigned raw transaction
	//scriptSig in unsigned transaction is serialized redeemScript of input P2SH transaction.
	rawTransaction, err := btcutils.NewRawTransaction(flagInputTx, flagAmount, redeemScript, scriptPubKey)
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
	//Sign transaction
	finalTransaction, err := signMultisigTransaction(rawTransactionWithHashCodeType, privateKeys, scriptPubKey, redeemScript, flagInputTx, flagAmount)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	return finalTransactionHex
}

// signMultisigTransaction signs a raw P2PKH transaction, given slice of private keys and the scriptPubKey, inputTx,
// redeemScript and amount to construct the final transaction.
func signMultisigTransaction(rawTransaction []byte, orderedPrivateKeys [][]byte, scriptPubKey []byte, redeemScript []byte, inputTx string, amount int) ([]byte, error) {
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
	//redeemScript length. To allow redeemScript > 255 bytes, we use OP_PUSHDATA2 and use two bytes to specify length
	var redeemScriptLengthBytes []byte
	var requiredOP_PUSHDATA int
	if len(redeemScript) < 255 {
		requiredOP_PUSHDATA = btcutils.OP_PUSHDATA1 //OP_PUSHDATA1 specifies next *one byte* will be length to be pushed to stack
		redeemScriptLengthBytes = []byte{byte(len(redeemScript))}
	} else {
		requiredOP_PUSHDATA = btcutils.OP_PUSHDATA2 //OP_PUSHDATA2 specifies next *two bytes* will be length to be pushed to stack
		redeemScriptLengthBytes = make([]byte, 2)
		binary.LittleEndian.PutUint16(redeemScriptLengthBytes, uint16(len(redeemScript)))
	}
	//Create scriptSig
	var buffer bytes.Buffer
	buffer.WriteByte(byte(btcutils.OP_0)) //OP_0 for Multisig off-by-one error
	for _, signature := range signatures {
		buffer.WriteByte(byte(len(signature) + 1)) //PUSH each signature. Add one for hash type byte
		buffer.Write(signature)                    // Signature bytes
		buffer.WriteByte(hashCodeType[0])          //hash type
	}
	buffer.WriteByte(byte(requiredOP_PUSHDATA)) //OP_PUSHDATA1 or OP_PUSHDATA2 depending on size of redeemScript
	buffer.Write(redeemScriptLengthBytes)       //PUSH redeemScript
	buffer.Write(redeemScript)                  //redeemScript
	scriptSig := buffer.Bytes()
	//Finally create transaction with actual scriptSig
	signedRawTransaction, err := btcutils.NewRawTransaction(inputTx, amount, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}

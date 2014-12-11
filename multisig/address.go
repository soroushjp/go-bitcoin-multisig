// Package multisig contains the main starting threads for each of the subcommands for go-bitcoin-multisig.
//
// address.go - Generating P2SH addresses.
package multisig

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

// GenerateAddress is the main thread for creating P2SH multisig addresses with the 'go-bitcoin-multisig address' subcommand.
// Takes flagM (number of keys required to spend), flagN (total number of keys)
// and flagPublicKeys (comma separated list of N public keys) as arguments.
func GenerateAddress(flagM int, flagN int, flagPublicKeys string) {
	//Convert public keys argument into slice of public key bytes with necessary tidying
	flagPublicKeys = strings.Replace(flagPublicKeys, "'", "\"", -1) //Replace single quotes with double since csv package only recognizes double quotes
	publicKeyStrings, err := csv.NewReader(strings.NewReader(flagPublicKeys)).Read()
	if err != nil {
		log.Fatal(err)
	}
	publicKeys := make([][]byte, len(publicKeyStrings))
	for i, publicKeyString := range publicKeyStrings {
		publicKeyString = strings.TrimSpace(publicKeyString)   //Trim whitespace
		publicKeys[i], err = hex.DecodeString(publicKeyString) //Get private keys as slice of raw bytes
		if err != nil {
			log.Fatal(err, "\n", "Offending publicKey: \n", publicKeyString)
		}
	}
	//Create redeemScript from public keys
	//redeemScript := btcutils.NewTwoOfTwoRedeemScript(publicKeys[0], publicKeys[1])
	redeemScript, err := btcutils.NewMOfNRedeemScript(flagM, flagN, publicKeys)
	if err != nil {
		log.Fatal(err)
	}
	redeemScriptHash, err := btcutils.Hash160(redeemScript)
	if err != nil {
		log.Fatal(err)
	}
	//Get P2SH address by base58 encodin with P2SH prefix 0x05
	P2SHAddress := base58check.Encode("05", redeemScriptHash)
	//Output P2SH and redeemScript
	fmt.Println("---------------------")
	fmt.Println("Your *P2SH ADDRESS* is:")
	fmt.Println(P2SHAddress)
	fmt.Println("Give this to sender funding multisig address with Bitcoin.")
	fmt.Println("---------------------")
	fmt.Println("---------------------")
	fmt.Println("Your *REDEEM SCRIPT* is:")
	fmt.Println(hex.EncodeToString(redeemScript))
	fmt.Println("Keep private and provide this to redeem multisig balance later.")
	fmt.Println("---------------------")
}

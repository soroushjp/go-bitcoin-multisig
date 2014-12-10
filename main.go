package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/multisig"

	"os"

	"gopkg.in/alecthomas/kingpin.v1"
)

var (
	app = kingpin.New("go-bitcoin-multisig", "A Bitcoin multisig transaction builder built in Go")

	cmdKeys        = app.Command("keys", "Generate public/private key pairs valid for use on Bitcoin network. **PSEUDORANDOM AND FOR DEMONSTRATION PURPOSES ONLY. DO NOT USE IN PRODUCTION.**")
	cmdKeysCount   = cmdKeys.Flag("count", "No. of key pairs to generate.").Default("1").Int()
	cmdKeysConcise = cmdKeys.Flag("concise", "Turn on concise output. Default is off (verbose output).").Default("false").Bool()

	cmdAddress           = app.Command("address", "Generate a multisig P2SH address with M-of-N requirements and set of public keys.")
	cmdAddressM          = cmdAddress.Flag("m", "M, the minimum number of keys needed to spend Bitcoin in M-of-N multisig transaction.").Required().Int()
	cmdAddressN          = cmdAddress.Flag("n", "N, the total number of possible keys that can be used to spend Bitcoin in M-of-N multisig transaction.").Required().Int()
	cmdAddressPublicKeys = cmdAddress.Flag("public-keys", "Comma separated list of private keys to sign with. Whitespace is stripped and quotes may be placed around keys. Eg. key1,key2,\"key3\"").PlaceHolder("PUBLIC-KEYS(Comma separated)").Required().String()

	cmdFund            = app.Command("fund", "Fund multisig address from a standard Bitcoin address.")
	cmdFundPrivateKey  = cmdFund.Flag("private-key", "Private key of bitcoin to send.").Required().String()
	cmdFundInputTx     = cmdFund.Flag("input-transaction", "Input transaction hash of bitcoin to send.").Required().String()
	cmdFundAmount      = cmdFund.Flag("amount", "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).").Required().Int()
	cmdFundDestination = cmdFund.Flag("destination", "Destination address. For P2SH, this should start with '3'.").Required().String()

	cmdSpend             = app.Command("spend", "Spend multisig balance by sending to a standard Bitcoin address.")
	cmdSpendPrivateKeys  = cmdSpend.Flag("private-keys", "Comma separated list of private keys to sign with. Whitespace is stripped and quotes may be placed around keys. Eg. key1,key2,\"key3\"").PlaceHolder("PRIVATE-KEYS(Comma separated)").Required().String()
	cmdSpendDestination  = cmdSpend.Flag("destination", "Public destination address to send bitcoins.").Required().String()
	cmdSpendRedeemScript = cmdSpend.Flag("redeemScript", "Hex representation of redeem script that matches redeem script in P2SH input transaction.").Required().String()
	cmdSpendInputTx      = cmdSpend.Flag("input-transaction", "Input transaction hash of bitcoin to send.").Required().String()
	cmdSpendAmount       = cmdSpend.Flag("amount", "Amount of bitcoin to send in satoshi (100,000,000 satoshi = 1 bitcoin).").Required().Int()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	//keys -- Generate public/private key pairs
	case cmdKeys.FullCommand():
		multisig.GenerateKeys(*cmdKeysCount, *cmdKeysConcise)

	//address -- Create a P2SH address
	case cmdAddress.FullCommand():
		multisig.GenerateAddress(*cmdAddressM, *cmdAddressN, *cmdAddressPublicKeys)

	case cmdFund.FullCommand():
		multisig.GenerateFund(*cmdFundPrivateKey, *cmdFundInputTx, *cmdFundAmount, *cmdFundDestination)

	case cmdSpend.FullCommand():
		multisig.GenerateSpend(*cmdSpendPrivateKeys, *cmdSpendDestination, *cmdSpendRedeemScript, *cmdSpendInputTx, *cmdSpendAmount)
	}
}

# go-bitcoin-multisig [![GoDoc](https://godoc.org/github.com/soroushjp/go-bitcoin-multisig?status.svg)](https://godoc.org/github.com/soroushjp/go-bitcoin-multisig)

Bitcoin [M-of-N Multisig](https://bitcoin.org/en/developer-guide#escrow-and-arbitration) Pay-to-ScriptHash (P2SH) Transaction Builder, built in [Go](https://golang.org/)

##Features

* Generate public/private key pairs valid for use in P2PKH/Multisig Bitcoin transactions
	- Up to 100 key pairs generated in one command.
	- **PSEUDORANDOM**. Do not use in production without adding randomness.

* Generate M-of-N multisig P2SH addresses given a set of specified public keys, M and N.
	- Up to 7-of-7 multisig.

* Fund a given multisig P2SH address from a standard Bitcoin wallet.

* Spend funds from multisig address to standard Bitcoin wallet.

##Build instructions

First, follow the instructions at [go-secp256k1](https://github.com/toxeus/go-secp256k1) to compile bitcoin/c-secp256k1, which is required for go-bitcoin-multisig.

Next, if you have your Go environment set up in the [usual way](https://golang.org/doc/code.html), simply run:

```bash
go get github.com/soroushjp/go-bitcoin-multisig

cd $GOPATH/src/github.com/soroushjp/go-bitcoin-multisig/

go install
```

And that's it! Now you can run the binary:

```bash
go-bitcoin-multisig --help
```

Or, if you don't have $GOPATH/bin in your $PATH environment variable, try:

```bash
$GOPATH/bin/go-bitcoin-multisig --help
```

##Usage

Full list of subcommands can be seen using go-bitcoin-multisig --help.
Flags for each subcommand can be seen using go-bitcoin-multisig <subcommand> --help

###Generate Keys

```bash
go-bitcoin-multisig keys <optional-flags>
```

Optional Flags:
  --count=1  No. of key pairs to generate.
  --concise  Turn on concise output. Default is off (verbose output).

**Example:**

```bash
go-bitcoin-multisig keys --count 3 --concise
```

### Generate P2SH Multisig Address

```bash
go-bitcoin-multisig address --m=M --n=N --public-keys=PUBLIC-KEYS(Comma separated, Hex format)
```

**Example:** (2-of-3 Multisig)

```bash
go-bitcoin-multisig address --m 2 --n 3 --public-keys 04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd,046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187,0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83 
```

### Fund Multisig Address

```bash
go-bitcoin-multisig fund --private-key=PRIVATE-KEY --input-tx=INPUT-TX --amount=AMOUNT --destination=DESTINATION
```

**Example:**

```bash
go-bitcoin-multisig fund --input-tx 3ad337270ac0ba14fbce812291b7d95338c878709ea8123a4d88c3c29efbc6ac --private-key 5JJyqG4bb15zqi7fTA4b227aUxQhBo1Ux6qX69ngeXYLr7fk2hs --destination 347N1Thc213QqfYCz3PZkjoJpNv5b14kBd --amount 65600
```

### Spend Multisig Funds

```bash
go-bitcoin-multisig spend --private-keys=PRIVATE-KEYS(Comma separated) --destination=DESTINATION --redeemScript=REDEEMSCRIPT --input-tx=INPUT-TX --amount=AMOUNT
```

**Example:**

```bash
go-bitcoin-multisig spend --input-tx 02b082113e35d5386285094c2829e7e2963fa0b5369fb7f4b79c4c90877dcd3d --amount 55600 --destination 18tiB1yNTzJMCg6bQS1Eh29dvJngq8QTfx --private-keys 5JruagvxNLXTnkksyLMfgFgf3CagJ3Ekxu5oGxpTm5mPfTAPez3,5JjHVMwJdjPEPQhq34WMUhzLcEd4SD7HgZktEh8WHstWcCLRceV --redeemScript 524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e8353ae
```

<sub><sup>*Bonus*: Above examples are [real multisig transactions](https://blockchain.info/tx/eeab3ef6cbea5f812b1bb8b8270a163b781eb7cde10ae5a7d8a3f452a57dca93) created with go-bitcoin-multisig. One lucky reader can redeem the balance in the real tx above with private key: *5Jmnhuc5gPWtTNczYVfL9yTbM6RArzXe3QYdnE9nbV4SBfppLc* #tip :)</sub></sup>

##Notes

* **Transaction Fees:**
	* The transaction fee is the difference between the specified amount when funding/spending multisig and balance of unspent input. 

* **Standardness:**
	* Will generate up to 7-of-7 m-of-n addresses, but warning generated for suspected non-standard addresses. 
	* m\*73 + n\*66 <= 496 is considered standard. Non-standard transactions may still get confirmed but may take much longer (testing with 7-of-7 multisig took 45 minutes with 60000 satoshi (~$0.22 current BTC price) transaction fee).
	* See [Pieter Wuille's answer on Stack Exchange](http://bitcoin.stackexchange.com/questions/23893/what-are-the-limits-of-m-and-n-in-m-of-n-multisig-addresses) for validity and standardness rules of Bitcoin protocol.

* **Order of keys:**
	* As per protocol rules, private keys provided to spend a multisig wallet have to be given in the same order (skipping keys is okay when m < n, but still in the same order) as given when the P2SH address was generated.

##License

go-bitcoin-multisig project is released under the terms of the MIT license. Thank you to [prettymuchbryce for his hellobitcoin project](https://github.com/prettymuchbryce/hellobitcoin) which provided both early code and inspiration for this project.

##Find out more

Built as a working demonstration of the P2SH M-of-N multisig functionality in the Bitcoin protocol and to serve as a easy to read Go reference implementation of raw multisig transactions. If you would like to use this code or similar functionality in your application, I'd love to hear from you so I can extend the project in more useful ways for the Bitcoin community. Reach out on Twitter @soroushjp or email me_AT_soroushjp.com.

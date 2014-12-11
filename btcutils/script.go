// Provides Bitcoin Script enum to improve code readability.
// See https://en.bitcoin.it/wiki/Script for full specification.
package btcutils

// OP_1 through OP_16
const (
	OP_1 = 81 + iota
	OP_2 //82
	OP_3 //83
	OP_4 //..
	OP_5
	OP_6
	OP_7
	OP_8
	OP_9
	OP_10
	OP_11
	OP_12
	OP_13
	OP_14 //..
	OP_15 //95
	OP_16 //96
)

// OP codes other than OP_1 through OP_16, used in P2SH Multisig transanctions.
const (
	OP_0             = 0
	OP_PUSHDATA1     = 76
	OP_PUSHDATA2     = 77
	OP_DUP           = 118
	OP_EQUAL         = 135
	OP_EQUALVERIFY   = 136
	OP_HASH160       = 169
	OP_CHECKSIG      = 172
	OP_CHECKMULTISIG = 174
)

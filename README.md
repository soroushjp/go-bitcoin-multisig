Bitcoin M-of-N Multisig P2SH implemented in Go
==============================================

Work in progress. Current master branch will generate a 2-of-2 P2SH multisig address with create_multisig_address.go, which can be funded with fund_p2sh.go and spent with spend_multisig.go. 

All transactions are native Go raw Bitcoin transactions. There is no need to run bitcoind or another Bitcoin node for use.

MIT License


package multisig

// import (
// 	"github.com/soroushjp/go-bitcoin-multisig/testutils"

// 	"testing"
// )

// func TestGenerateFund(t *testing.T) {
// 	testPrivateKeyWIF := "5JJyqG4bb15zqi7fTA4b227aUxQhBo1Ux6qX69ngeXYLr7fk2hs"
// 	testInputTx := "3ad337270ac0ba14fbce812291b7d95338c878709ea8123a4d88c3c29efbc6ac"
// 	testAmount := 65600
// 	testP2SHDestination := "347N1Thc213QqfYCz3PZkjoJpNv5b14kBd"
// 	testFinalTransanctionHex := "0100000001acc6fb9ec2c3884d3a12a89e7078c83853d9b7912281cefb14bac00a2737d33a000000008b483045022100f01a750718505928888531007f116718ea3331bf912f4853a4c0392c4ee9ad05022059e52850e181821c678fbae92cc139886e8683de8e354672c6b2d35661743b1301410431393af9984375830971ab5d3094c6a7d02db3568b2b06212a7090094549701bbb9e84d9477451acc42638963635899ce91bacb451a1bb6da73ddfbcf596bddfffffffff01400001000000000017a9141a8b0026343166625c7475f01e48b5ede8c0252e8700000000"

// 	GenerateFund(testPrivateKeyWIF, testInputTx, testAmount, testP2SHDestination)

// 	if finalTransactionHex != testFinalTransanctionHex {
// 		testutils.CompareError(t, "Generated funding transaction different from expected transaction.", testFinalTransanctionHex, finalTransactionHex)
// 	}
// }

package testutils

import "testing"

// compareError formats an error message nicely to print the error, the expected output and received output.
// expected and got may be of any type acceptable for t.Error args (ie. any args acceptable for fmt.Println)
func CompareError(t *testing.T, errMessage string, expected interface{}, got interface{}) {
	t.Error(
		errMessage,
		"\n",
		"Expected:\n",
		expected,
		"\n",
		"Got: \n",
		got,
	)
}

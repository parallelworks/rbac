// Package untested has statements and no test files, which go test -list built with -cover says
// how much of is covered.
package untested

// Answer is a statement to cover.
func Answer() int { return 42 }

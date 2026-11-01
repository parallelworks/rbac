// Package aggregate holds tests that shards' own tests run in shards: one whose body reads what its
// subtests did, as one that counts what they found does, and others for the shards to place.
package aggregate

import (
	"fmt"
	"testing"
)

func TestParentOfSubtests(t *testing.T) {
	ran := 0
	for i := range 3 {
		t.Run(fmt.Sprint(i), func(t *testing.T) { ran++ })
	}
	if ran != 3 {
		t.Errorf("%d of its 3 subtests ran", ran)
	}
}

func TestA(t *testing.T) {}

func TestB(t *testing.T) {}

func TestC(t *testing.T) {}

func TestD(t *testing.T) {}

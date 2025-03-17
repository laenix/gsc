package examples_test

import (
	"testing"

	"github.com/laenix/gsc/examples"
)

func TestAES_test(t *testing.T) {
	examples.AES_test()
}

func TestDES_test(t *testing.T) {
	examples.DES_test()
}

func TestBlowfish_test(t *testing.T) {
	examples.Blowfish_test()
}

func TestTwofish_test(t *testing.T) {
	examples.Twofish_test()
}

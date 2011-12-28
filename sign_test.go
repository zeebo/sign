package sign_test

import (
	"log"
	"sign"
	"testing"
)

var s = sign.Signer{[]byte("foo")}

func ExampleSigner() {
	s := sign.Signer{[]byte("my secret key")}
	x := "some complicated object"
	val, err := s.Sign(x)
	if err != nil {
		log.Fatal(err)
	}

	//print our signature
	log.Println(val)

	x = ""
	//reload it with a 10 second max duration
	if err := s.Unsign(val, &x, 10e9); err != nil {
		log.Fatal(err)
	}
	//prints the complicated object
	log.Println(x)
}

func TestBadSignature(t *testing.T) {
	var x string
	if err := s.Unsign("bad signature", &x, 0); err == nil {
		t.Fatal("Did not recognize bad signature")
	}
}

func TestTimeout(t *testing.T) {
	x := "foo string"
	val, err := s.Sign(x)
	if err != nil {
		t.Fatal(err)
	}

	//way more than 1 nanosecond has passed.
	if err := s.Unsign(val, &x, 1); err != sign.SignatureExpired {
		t.Fatal("Signature did not expire")
	}
}

func TestUnsign(t *testing.T) {
	x := "foo string"
	val, err := s.Sign(x)
	if err != nil {
		t.Fatal(err)
	}

	x = ""
	if err := s.Unsign(val, &x, 0); err != nil {
		t.Fatal(err)
	}

	if x != "foo string" {
		t.Fatal("Unsign did not restore to original state")
	}
}

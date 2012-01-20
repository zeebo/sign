package sign

import (
	"log"
	"testing"
)

var s = Signer{[]byte("foo")}

func ExampleSigner() {
	s := Signer{[]byte("my secret key")}
	var x string = "some complicated object"
	sig, err := s.Sign(x)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Our signature:", sig)

	var y string
	if err := s.Unsign(sig, &y, 10e9); err != nil {
		log.Fatal(err)
	}

	if y == x {
		log.Print("value loaded sucessfully!")
	}
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
	if err := s.Unsign(val, &x, 1); err != SignatureExpired {
		t.Fatal("Signature did not expire:", err)
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

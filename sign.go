//Package sign implements cryptographic signatures for Go structures
package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const sep = ":"

//Error types
var (
	BadSignature     = errors.New("Bad Signature")
	SignatureExpired = errors.New("Signature Expired")
)

type Signer struct {
	Key []byte
}

//timestamp returns a URL-safe base64 encoded nanosecond timestamp
func timestamp() (string, error) {
	now := time.Now()

	var buf bytes.Buffer
	enc := base64.NewEncoder(base64.URLEncoding, &buf)
	if _, err := fmt.Fprintf(enc, "%d", now.UnixNano()); err != nil {
		return "", err
	}
	//must close to finish writing to buffer
	if err := enc.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

//Signature returns a URL-safe base64 encoded signature for the given string
func (s Signer) Signature(val string) (string, error) {
	hm := hmac.NewSHA1(s.Key)
	hm.Write([]uint8(val))

	var buf bytes.Buffer
	enc := base64.NewEncoder(base64.URLEncoding, &buf)
	if _, err := enc.Write(hm.Sum(nil)); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

//Sign returns a URL-safe, sha1 signed base64 encoded string that represents
//the given object using json encoding. It includes a timestamp of the creation
//of the signature for expiration times.
func (s Signer) Sign(obj interface{}) (string, error) {
	var buf bytes.Buffer

	b64enc := base64.NewEncoder(base64.URLEncoding, &buf)

	jsonenc := json.NewEncoder(b64enc)
	if err := jsonenc.Encode(obj); err != nil {
		return "", err
	}
	if err := b64enc.Close(); err != nil {
		return "", err
	}

	//grab our URL-safe base64 encoded representation of our object
	ts, err := timestamp()
	if err != nil {
		return "", err
	}

	//compute the signature
	value := fmt.Sprintf("%s%s%s", buf.String(), sep, ts)
	signature, err := s.Signature(value)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s%s", value, sep, signature), nil
}

//Unsign loads the signature data into the object passed in using the json
//library. Any value greater than 0 for age makes the signature expire after
//that many nanoseconds.
func (s Signer) Unsign(data string, obj interface{}, age time.Duration) error {
	if strings.Count(data, ":") != 2 {
		return BadSignature
	}

	//grab now before we do a buncha computations
	now := time.Now()

	chunks := strings.SplitN(data, sep, 3)
	value, ts, sig := chunks[0], chunks[1], chunks[2]

	//recompute our signature
	csig, err := s.Signature(fmt.Sprintf("%s%s%s", value, sep, ts))
	if err != nil {
		return err
	}

	if len(csig) != len(sig) {
		return BadSignature
	}

	if subtle.ConstantTimeCompare([]uint8(csig), []uint8(sig)) != 1 {
		return BadSignature
	}

	//check our timestamp
	if age > 0 {
		tsbyte, err := base64.URLEncoding.DecodeString(ts)
		if err != nil {
			return BadSignature
		}

		cnow, err := strconv.ParseInt(string(tsbyte), 10, 64)
		if err != nil {
			return BadSignature
		}

		onow := time.Unix(0, cnow)

		if now.Sub(onow) > age {
			return SignatureExpired
		}
	}

	//decode value
	valbyte, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return BadSignature
	}

	buf := bytes.NewBuffer(valbyte)
	dec := json.NewDecoder(buf)

	return dec.Decode(obj)
}

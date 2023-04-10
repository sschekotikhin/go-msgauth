package dkim_test

import (
	"bytes"
	"log"
	"strings"

	"github.com/sschekotikhin/go-msgauth/dkim"
	"github.com/sschekotikhin/openssl"
)

var (
	mailString string
	privateKey openssl.PrivateKey
)

func ExampleSign() {
	r := strings.NewReader(mailString)

	options := &dkim.SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   privateKey,
	}

	var b bytes.Buffer
	if err := dkim.Sign(&b, r, options); err != nil {
		log.Fatal(err)
	}
}

func ExampleVerify() {
	r := strings.NewReader(mailString)

	verifications, err := dkim.Verify(r)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range verifications {
		if v.Err == nil {
			log.Println("Valid signature for:", v.Domain)
		} else {
			log.Println("Invalid signature for:", v.Domain, v.Err)
		}
	}
}

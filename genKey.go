package main

import (
	"crypto/rand"
	"flag"
	"io/ioutil"
	"log"

	"code.google.com/p/go.crypto/otr"
)

var (
	fname = flag.String("fname", "keyfile", "Specifies the name of the keyfile")
)

func main() {

	newKey := new(otr.PrivateKey)

	newKey.Generate(rand.Reader)

	keyBytes := newKey.Serialize(nil)

	err := ioutil.WriteFile(*fname, keyBytes, 0700)
	checkErr(err)

	log.Printf("Done! Fingerprint: %v", newKey.Fingerprint())
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln("Error:", err)
	}
}

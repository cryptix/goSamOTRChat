package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"code.google.com/p/go.crypto/otr"
	"github.com/cryptix/goSam"
)

var (
	keyFile = flag.String("key", "keyfile", "The private keyfile to use.")

	otrPrivKey   otr.PrivateKey
	otrConv      otr.Conversation
	otrSecChange otr.SecurityChange
)

func main() {
	flag.Parse()

	sam, err := goSam.NewDefaultClient()
	checkErr(err)
	defer sam.Close()

	log.Println("Client Created")

	keyBytes, err := ioutil.ReadFile(*keyFile)
	checkErr(err)

	rest, ok := otrPrivKey.Parse(keyBytes)
	if !ok {
		log.Fatalf("ERROR: Failed to parse private key %s\n", *keyFile)
	}
	if len(rest) > 0 {
		log.Fatalln("ERROR: data remaining after parsing private key")
	}

	otrConv.PrivateKey = &otrPrivKey
	otrConv.FragmentSize = 5000

	conn, err := sam.Accept()
	checkErr(err)
	samReader := bufio.NewReader(conn)

	// first line is from sam, incomming address
	line, err := samReader.ReadString('\n')
	checkErr(err)
	log.Println("Conenction From: ", line)

	bufStdin := bufio.NewReader(os.Stdin)
	msgLoop(conn, samReader, bufStdin)
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

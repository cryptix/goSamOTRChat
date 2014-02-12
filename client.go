package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"code.google.com/p/go.crypto/otr"
	"github.com/cryptix/goSam"
)

// cumbersome - you need to paste the destination to connect to here....
const addr = "ir-543rsfsTZBjj409PJNtj5l2zK50SkSSgnuxl4rQgBsanS8OzObkp1Ri4ZqWSd9EN8~VBHiakEFkgDh2zTZ5OnmSediVQVkAe6q2BXwLwO4GSNkwFLBhevkj39FrAAISveGLrZo5imesCAhdch8OGZ13Os3VmG5gMw37Pa7MOcbXMyepqANCP5VunGa1pb6OWS0Hd0km9giI9jKn13i1ZRa~d9zJ11VJdtL~vth3gpbH7sGxjO9r-x6z7oKGEiVcGkFzEC50U3xtalDA3H3mWEeHODkYpEQJ5Q~~bdBW1VPwysHMRwdAUMfRCEpp2YF909Si~f7HtgMtLdPfb7QHIXNxXE2Hd1lA3WBQIOe8LMEFTd700uX8XWKLD55QsX8mDYDXRhaxbqKwWYZ~wbGwHSQqq2iYUa4PaPqUTGxNjDOKPktRqq59JWvN0Pju~rv5bTsM42gZmqk8dn71Q8netLjePwcrYdruyqm1ZiM7dQD0EePQAyqs5C0bn3NE28AAAAZkdE8kNCydRiEiymE8fLMnvwzPefTJWY~SdZKv6tTRjB2wPkT~xlA~mrgGd0XYuFJtObuu2Fdrhu9KYX41bTRHXBl5XQP7Zt7jJbcTBfs-i8YPiKgLIC0osI~g9HENOHrcZTqu-1ZJSxIet1twahB1ovhfbTaG0Yb24lzQUgDr4od6uTixxwBomv2iMqGNc2EFOeNmnN1SEzE5LEw-5aeTYxuhJbJgniVGzQe5lDoCV5X4uBfIGkx6iQ4N4C35F850jX~a3zmWOOcWmOUiEt54cgaqXbL6pcuZECKE1ECJN2T0Cxbamr9Pdcpar0sEcowFiI83lcJmFZXUkA5o9PqlfCC6gvOrKF~BXTV1-~kmcXcAg6"

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

	id, _, err := sam.CreateStreamSession("")
	checkErr(err)

	newC, err := goSam.NewDefaultClient()
	checkErr(err)

	err = newC.StreamConnect(id, addr)
	checkErr(err)

	log.Println("Stream connected. Sending OTR Query")
	fmt.Fprintf(newC.SamConn, "%s.", otr.QueryMessage)

	bufStdin := bufio.NewReader(os.Stdin)

	samReader := bufio.NewReader(newC.SamConn)
	msgLoop(newC.SamConn, samReader, bufStdin)
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

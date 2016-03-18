package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codegangsta/cli"
	"github.com/cryptix/go/logging"
	"github.com/cryptix/goSam"
	"golang.org/x/crypto/otr"
)

const appName = "goSamOTRChat"

var (
	l            = logging.Logger(appName)
	sam          *goSam.Client
	keyFile      string
	otrPrivKey   otr.PrivateKey
	otrConv      otr.Conversation
	otrSecChange otr.SecurityChange
)

func main() {
	logging.SetupLogging(nil)
	app := cli.NewApp()
	app.Name = appName
	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: "debug", Usage: "output debug information from sam client"},
		cli.StringFlag{Name: "key,k", Value: "keyfile", Usage: "The private keyfile to use."},
	}
	app.Commands = []cli.Command{
		{
			Name:   "server",
			Action: cmdServer,
			Before: parseKey,
		},
		{
			Name:   "client",
			Action: cmdClient,
			Before: parseKey,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "dest,d", Usage: "the i2p destination address to connect to"},
			},
		},
		{
			Name:   "genkey",
			Action: cmdGenKey,
		},
	}

	app.Run(os.Args)
}

func parseKey(ctx *cli.Context) (err error) {
	keyFile = ctx.GlobalString("key")
	if keyFile == "" {
		logging.CheckFatal(errors.New("flag key can't be empty"))
	}
	if ctx.GlobalBool("debug") {
		goSam.ConnDebug = true
	}
	sam, err = goSam.NewDefaultClient()
	check(err)

	l.Info("SAM Client Created")
	var keyBytes []byte
	keyBytes, err = ioutil.ReadFile(keyFile)
	check(err)
	rest, ok := otrPrivKey.Parse(keyBytes)
	if !ok {
		logging.CheckFatal(fmt.Errorf("ERROR: Failed to parse private key %s\n", keyFile))
	}
	if len(rest) > 0 {
		logging.CheckFatal(errors.New("ERROR: data remaining after parsing private key"))
	}
	otrConv.PrivateKey = &otrPrivKey
	otrConv.FragmentSize = 5000
	return nil
}

func cmdGenKey(ctx *cli.Context) {
	keyFile := ctx.GlobalString("key")
	newKey := new(otr.PrivateKey)
	newKey.Generate(rand.Reader)
	keyBytes := newKey.Serialize(nil)
	err := ioutil.WriteFile(keyFile, keyBytes, 0700)
	check(err)
	l.Infof("Done! Fingerprint: %x", newKey.Fingerprint())
}

func cmdClient(ctx *cli.Context) {
	dest := ctx.String("dest")
	if dest == "" {
		logging.CheckFatal(errors.New("flag dest can't be empty"))
	}
	id, _, err := sam.CreateStreamSession("")
	check(err)
	newC, err := goSam.NewDefaultClient()
	check(err)
	err = newC.StreamConnect(id, dest)
	check(err)
	l.Info("Stream connected. Sending OTR Query")
	fmt.Fprintf(newC.SamConn, "%s.", otr.QueryMessage)
	bufStdin := bufio.NewReader(os.Stdin)
	samReader := bufio.NewReader(newC.SamConn)
	msgLoop(newC.SamConn, samReader, bufStdin)
}

func cmdServer(ctx *cli.Context) {
	conn, err := sam.Accept()
	check(err)
	samReader := bufio.NewReader(conn)
	// first line is from sam, incomming address
	line, err := samReader.ReadString('\n')
	check(err)
	l.Info("Conenction From: ", line)
	bufStdin := bufio.NewReader(os.Stdin)
	msgLoop(conn, samReader, bufStdin)
}

func check(err error) {
	if err != nil {
		l.Fatal(err)
	}
}

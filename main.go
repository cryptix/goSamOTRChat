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

	app.Before = before

	app.Commands = []cli.Command{
		{
			Name:   "server",
			Action: cmdServer,
		},
		{
			Name:   "client",
			Action: cmdClient,
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

func before(ctx *cli.Context) (err error) {
	keyFile = ctx.String("key")
	if keyFile == "" {
		logging.CheckFatal(errors.New("flag key can't be empty"))
	}
	sam, err = goSam.NewDefaultClient()
	logging.CheckFatal(err)

	if ctx.Bool("debug") {
		sam.ToggleVerbose()
	}
	l.Notice("SAM Client Created")
	var keyBytes []byte
	keyBytes, err = ioutil.ReadFile(keyFile)
	logging.CheckFatal(err)

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
	logging.CheckFatal(err)
	l.Noticef("Done! Fingerprint: %v", newKey.Fingerprint())
}

func cmdClient(ctx *cli.Context) {
	dest := ctx.String("dest")
	if dest == "" {
		logging.CheckFatal(errors.New("flag dest can't be empty"))
	}
	id, _, err := sam.CreateStreamSession("")
	logging.CheckFatal(err)

	newC, err := goSam.NewDefaultClient()
	logging.CheckFatal(err)

	err = newC.StreamConnect(id, dest)
	logging.CheckFatal(err)

	l.Notice("Stream connected. Sending OTR Query")
	fmt.Fprintf(newC.SamConn, "%s.", otr.QueryMessage)

	bufStdin := bufio.NewReader(os.Stdin)

	samReader := bufio.NewReader(newC.SamConn)
	msgLoop(newC.SamConn, samReader, bufStdin)
}

func cmdServer(ctx *cli.Context) {
	conn, err := sam.Accept()
	logging.CheckFatal(err)
	samReader := bufio.NewReader(conn)

	// first line is from sam, incomming address
	line, err := samReader.ReadString('\n')
	logging.CheckFatal(err)
	l.Notice("Conenction From: ", line)

	bufStdin := bufio.NewReader(os.Stdin)
	msgLoop(conn, samReader, bufStdin)
}

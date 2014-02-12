package main

import (
	"bufio"
	"log"
	"net"

	"code.google.com/p/go.crypto/otr"
)

func msgLoop(samConn net.Conn, samReader, stdinReader *bufio.Reader) {
	for {
		fromPeer, err := samReader.ReadBytes('.')
		checkErr(err)
		// log.Printf("<RAW> Msg From Peer: %s\n", string(fromPeer))

		out, encrypted, otrSecChange, msgToPeer, err := otrConv.Receive(fromPeer)
		checkErr(err)

		if len(out) > 0 {
			log.Print("<OTR>", string(out))
		}

		if !encrypted {
			log.Println("<OTR> Conversation not yet encrypted!!!")
		}

		if len(msgToPeer) > 0 {
			log.Printf("<OTR> Transmitting %d messages.\n", len(msgToPeer))
			for _, msg := range msgToPeer {
				n, err := samConn.Write(msg)
				checkErr(err)

				if n < len(msg) {
					log.Fatalln("<OTR> some bytes were not send to peer..")
				}
			}
		}

		switch otrSecChange {
		case otr.NoChange:
			if encrypted {
				sendStdinMsg(samConn, stdinReader)
			}

		case otr.NewKeys:
			log.Printf("<OTR> Key exchange completed. SSID:%x\n", otrConv.SSID)
			sendStdinMsg(samConn, stdinReader)

		case otr.ConversationEnded:
			log.Println("<OTR> Conversation ended.")
			return

		default:
			log.Printf("<OTR> SMPState: %d - not yet implemented!... :(", otrSecChange)
		}
	}
}

func sendStdinMsg(samConn net.Conn, stdinReader *bufio.Reader) {
	// read keyboard input
	log.Println("<OTR> Reading stdin")
	chatInput, err := stdinReader.ReadBytes('\n')
	checkErr(err)

	// prepare message to peer
	msgToPeer, err := otrConv.Send(chatInput)
	checkErr(err)

	for _, msg := range msgToPeer {
		n, err := samConn.Write(msg)
		checkErr(err)

		if n < len(msg) {
			log.Fatalln("<OTR> some bytes were not send to peer..")
		}
	}
}

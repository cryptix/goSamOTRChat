package main

import (
	"bufio"
	"net"

	"golang.org/x/crypto/otr"
)

func msgLoop(samConn net.Conn, samReader, stdinReader *bufio.Reader) {
	for {
		fromPeer, err := samReader.ReadBytes('.')
		check(err)
		// l.Warningf("<RAW> Msg From Peer: %s\n", string(fromPeer))
		out, encrypted, otrSecChange, msgToPeer, err := otrConv.Receive(fromPeer)
		check(err)
		if len(out) > 0 {
			l.Infof("<OTR>\n%s", string(out))
		}
		if !encrypted {
			l.Warning("<OTR> Conversation not yet encrypted!!!")
		}
		if len(msgToPeer) > 0 {
			l.Warningf("<OTR> Transmitting %d messages.\n", len(msgToPeer))
			for _, msg := range msgToPeer {
				n, err := samConn.Write(msg)
				check(err)
				if n < len(msg) {
					l.Fatal("<OTR> some bytes were not send to peer..")
				}
			}
		}
		switch otrSecChange {
		case otr.NoChange:
			if encrypted {
				sendStdinMsg(samConn, stdinReader)
			}
		case otr.NewKeys:
			l.Warningf("<OTR> Key exchange completed.\nFingerprint:%x\nSSID:%x\n",
				otrConv.TheirPublicKey.Fingerprint(),
				otrConv.SSID,
			)
			sendStdinMsg(samConn, stdinReader)
		case otr.ConversationEnded:
			l.Warning("<OTR> Conversation ended.")
			return
		default:
			l.Warningf("<OTR> SMPState: %d - not yet implemented!... :(", otrSecChange)
		}
	}
}

func sendStdinMsg(samConn net.Conn, stdinReader *bufio.Reader) {
	// read keyboard input
	l.Info("<OTR> Reading stdin")
	chatInput, err := stdinReader.ReadBytes('\n')
	check(err)
	// prepare message to peer
	msgToPeer, err := otrConv.Send(chatInput)
	check(err)
	for _, msg := range msgToPeer {
		n, err := samConn.Write(msg)
		check(err)
		if n < len(msg) {
			l.Fatal("<OTR> some bytes were not send to peer..")
		}
	}
}

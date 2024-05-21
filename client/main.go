package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"

	"github.com/neekrasov/dh-ec/ec"
	"github.com/neekrasov/dh-ec/tcp"
	"github.com/pkg/errors"
)

func Client() error {
	fmt.Println("Initialize connections...")
	serverConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return errors.Wrap(err, "failed to initialize registrar connection")
	}
	defer serverConn.Close()

	c := ec.Secp256k1()
	Ka, err := ec.RandNum(2048)
	if err != nil {
		return errors.Wrap(err, "failed to generate random number")
	}
	Pa := c.PubKey(Ka)

	PaBytes, err := json.Marshal(Pa)
	if err != nil {
		return errors.Wrap(err, "failed to marshall Pa")
	}

	if err := tcp.Send(serverConn, PaBytes); err != nil {
		return errors.Wrap(err, "failed to send Pa bytes to server")
	}

	var PbBytes []byte
	if err := tcp.Read(bufio.NewReader(serverConn), &PbBytes); err != nil {
		return errors.Wrap(err, "failed to read server Pb bytes")
	}

	var Pb ec.Point
	if err := json.Unmarshal(PbBytes, &Pb); err != nil {
		return errors.Wrap(err, "failed to unmarshall Pb")
	}

	fmt.Println("Generated secret key: ", c.SecretKey(Ka, &Pb).X)
	return nil
}

func main() {
	if err := Client(); err != nil {
		fmt.Println(err.Error())
	}
}

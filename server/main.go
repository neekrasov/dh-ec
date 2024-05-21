package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"

	"github.com/neekrasov/dh-ec/ec"
	"github.com/neekrasov/dh-ec/tcp"
	"github.com/pkg/errors"
)

func Server() error {
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		return errors.Wrap(err, "start server failed")
	}
	defer listener.Close()

	c := ec.Secp256k1()
	Kb, err := ec.RandNum(2048)
	if err != nil {
		return errors.Wrap(err, "failed to generate random number")
	}
	Pb := c.PubKey(Kb)
	fmt.Println("Server ready to accept connections")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error accepting connection: %s", err.Error())
			continue
		}
		go handleConnection(conn, c, Kb, Pb)
	}
}

func handleConnection(
	conn net.Conn,
	c *ec.EC,
	Kb *big.Int,
	Pb *ec.Point,
) {
	var PaBytes []byte
	if err := tcp.Read(bufio.NewReader(conn), &PaBytes); err != nil {
		log.Printf("Failed to read Pa bytes: %s", err.Error())
		return
	}

	var Pa ec.Point
	if err := json.Unmarshal(PaBytes, &Pa); err != nil {
		log.Print("Failed to unmarhall Pa bytes")
		return
	}

	PbBytes, err := json.Marshal(Pb)
	if err != nil {
		log.Printf("failed to marshal Pb: %s", err.Error())
		return
	}

	if err = tcp.Send(conn, PbBytes); err != nil {
		log.Printf("failed to send Pb bytes to client: %s", err.Error())
		return
	}

	fmt.Println("Generated secret key: ", c.SecretKey(Kb, &Pa).X)
}

func main() {
	if err := Server(); err != nil {
		fmt.Println(err.Error())
	}
}

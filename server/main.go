package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certificate.crt", "private.key")
	if err != nil {
		log.Fatalf("failed to read key pair: %s\n", err.Error())
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	listener, err := tls.Listen("tcp", "localhost:8000", config)
	if err != nil {
		log.Fatalf("failed to start TLS server: %s\n", err.Error())
	}
	fmt.Println("accepting connections:")
	buffer := make([]byte, 1024)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept a connection: %s\n", err.Error())
			continue
		}

		fmt.Printf("accepted connection: %s\n", conn.LocalAddr().String())
		n, err := conn.Read(buffer)
		fmt.Printf("received data: %s\n", string(buffer[:n]))
		if err != nil {
			log.Printf("failed to read from connection: %v\n", err.Error())
		} else {
			fmt.Printf("received data: %s\n", string(buffer[:n]))
		}
		conn.Close()
	}
}

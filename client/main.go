package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Println("implementing TLS")

	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		panic(err)
	}
	var randomByte [28]byte

	rand.Read(randomByte[:])

	random := Random{
		UnixTime:    uint32(time.Now().Unix()),
		RandomBytes: randomByte,
	}
	clientHello := ClientHello{
		ProtocolVersion:    ProtocolVersionV,
		Random:             random,
		SessionID:          []byte{},
		CompressionMethods: []byte{0x00},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	TLSRecord := TLSRecord{}
	HandshakeMessage := HandshakeMessage{}
	ServerHello := ServerHello{}
	clientHelloBytes := clientHello.Serialize()
	TLSRecordBytes := TLSRecord.Serialize(clientHelloBytes)
	fmt.Printf("length _ %v\n", len(TLSRecordBytes))
	conn.Write(TLSRecordBytes)

	respBuffer := make([]byte, 4096)

	_, err = conn.Read(respBuffer) // this return three Head Back to Back ServerHello, Certificate, ServerHello Done
	respReader := bytes.NewReader(respBuffer)
	if err != nil {
		panic(err)
	}
	fmt.Println("/////////// First Record (this single request carries 3 headers; they are not separate requests, just parsed one after another from the same response) ////////////////////\n")

	TLSRecord.Parse(respReader) // first Record parsed from stream; next Record follow in same response like one request from client and three response from server.
	// in this record the handshake meesage will bring CERTIFICATE
	// fmt.Printf("TLSRecord.ContentType: %v (means Handshake)\n", TLSRecord.ContentType)
	// fmt.Printf("TLSRecord.ProtocolVersion: %v\n", TLSRecord.ProtocolVersion)
	// fmt.Printf("TLSRecord.Length: %v\n", TLSRecord.Length)

	HandshakeMessage.Parse(bytes.NewReader(TLSRecord.Payload))
	fmt.Printf("HandshakeMessage.MessageType: %v\n", HandshakeMessage.MessageType)
	fmt.Printf("HandshakeMessage.Length: %v\n", HandshakeMessage.Length)
	ServerHello.Parse(bytes.NewReader(HandshakeMessage.Payload))

	fmt.Printf("ServerHello.ProtocolVersion: %v\n", ServerHello.ProtocolVersion)
	fmt.Printf("ServerHello.Random: %v\n", ServerHello.Random)
	fmt.Printf("ServerHello.SessionID: %v\n", ServerHello.SessionID)
	fmt.Printf("ServerHello.CipherSuite: %v\n", ServerHello.CipherSuite)
	fmt.Printf("ServerHello.CompressionMethod: %v (0 = no compression; client decided no compression)\n", ServerHello.CompressionMethod)

	fmt.Println("\n/////////// Second Record ////////////////////\n") // remember second record is always a response from server after first response so think of it's like client makes a single request ans server responded it three times with differnt data
	TLSRecord.Parse(respReader)                                       // in this record the handshake meesage will bring CERTIFICATE
	HandshakeMessage.Parse(bytes.NewReader(TLSRecord.Payload))
	fmt.Printf("HandshakeMessage.MessageType: %v\n", HandshakeMessage.MessageType)
	fmt.Printf("HandshakeMessage.Length: %v\n", HandshakeMessage.Length)

	certs := ParseCertificates(bytes.NewReader(HandshakeMessage.Payload))
	for _, cert := range certs {
		fmt.Printf("cert.Issuer.Country: %v\n", cert.Issuer.Country)
	}
	// and the most important thing in TLS server sends certificate chain 

	fmt.Println("\n/////////// Third Record ////////////////////\n")
	TLSRecord.Parse(respReader)
	HandshakeMessage.Parse(bytes.NewReader(TLSRecord.Payload))
	fmt.Printf("HandshakeMessage.MessageType: %v\n", HandshakeMessage.MessageType)
	fmt.Printf("HandshakeMessage.Length: %v\n", HandshakeMessage.Length)
	
	//now the server has sent the three records ServerHello, Certificate,  and ServerHelloDone;
	//it's client to sent back the ClientKey,

	conn.Write(TLSRecordBytes)

}

// 0  → HelloRequest       (rare / mostly obsolete)
// 1  → ClientHello        (client → server)
// 2  → ServerHello        (server → client)
// 4  → NewSessionTicket   (TLS 1.3 session reuse)
// 8  → EncryptedExtensions(TLS 1.3)
// 11 → Certificate        (server/client cert)
// 12 → ServerKeyExchange  (TLS 1.2 and below)
// 13 → CertificateRequest (server asks client cert)
// 14 → ServerHelloDone    (TLS 1.2 end of server hello)
// 15 → CertificateVerify  (prove ownership of cert)
// 16 → ClientKeyExchange  (TLS 1.2 key exchange)
// 20 → Finished           (both sides)
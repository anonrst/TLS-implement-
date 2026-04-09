# TLS

First, TLS stands for Transport Layer Security. Its job is to secure data in packet transmission from being leaked to attackers. However, its job isn't to organize DataPackets—TCP does this.

So it's built on top of TCP or UDP and some other protocols. Before sending a single data packet over the internet, what TCP does is establish a secure connection.

For establishing this connection, both server and client have to exchange keys and decide on a cipher suite they both will be using. A cipher suite is just like an algorithm that both (server and client) will agree to use in their encryption.

Let's understand serialization. Serialization is converting objects into any universal format that any language could understand—this could be JSON, YAML, but in this case it's raw bytes.

Another thing in TLS: every Message Record that TLS sends has a MessageType that represents what the server is sending or requesting.
 0  → HelloRequest       (rare / mostly obsolete)
 1  → ClientHello        (client → server)
 2  → ServerHello        (server → client)
 4  → NewSessionTicket   (TLS 1.3 session reuse)
 8  → EncryptedExtensions(TLS 1.3)
 11 → Certificate        (server/client cert)
 12 → ServerKeyExchange  (TLS 1.2 and below)
 13 → CertificateRequest (server asks client cert)
 14 → ServerHelloDone    (TLS 1.2 end of server hello)
 15 → CertificateVerify  (prove ownership of cert)
 16 → ClientKeyExchange  (TLS 1.2 key exchange)
 20 → Finished           (both sides)

type Extension struct {
	Type uint16
	Data []byte
}

type ServerHello struct {
	ProtocolVersion   [2]byte
	Random            Random
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	Extension         []Extension
}

type Random struct {
	UnixTime    uint32
	RandomBytes [28]byte
}


type ClientHello struct {
	ProtocolVersion    [2]byte
	Random             Random
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []Extension
}
# TLS record is the structure that every request or response between client and server for establishing this secure connection has to sends in, so this mean that in every request TLSRecord is like Wrapper like headers and body in HTTPRequest
type TLSRecord struct { //so think this is the actual HTTPRequest and it's has body and headers, and think ContentType is also a header andif header is HandshakeMessage this means that it's body is going to have a wrapper of HandshakeMessage so the contenttype could be like 
	ContentType     byte
	ProtocolVersion [2]byte
	Length          uint16
	Payload         []byte
}
# so this is the struct inside every TLSRecord storing the type of message and that message.
type HandshakeMessage struct {
	MessageType byte
	Length      [3]byte
	Payload     []byte
}
// Don't be confused if HandshakeMessage is in every TLSRecord—what makes it necessary to wrap HandshakeMessage in TLSRecord? Why not send only HandshakeMessage? Just think of HandshakeMessage as the Body in an HTTPRequest, which isn't necessary every time in every Record. Let's take an example of sending ChangeCipherSpec to the server, which looks like this: `changeCipherSpec := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}`. This is a TLSRecord where the first byte is `0x14`, which means the Content Type. 
<!-- A complete TLS 1.2 handshake requires this full exchange:
first the client will start the setting this secure connection and in all of this handshake meaning is same as communicating via request and responses.
Client                          Server
  │                               │
  │──── ClientHello ─────────────▶│        so first client will send a clientHello request, remember every going to server is First wrapped in Handshale message and that that Handshake message is wrapped IN TLSRecord this means that TLSRecord in parent Wrapper 
  │◀─── ServerHello ──────────────│         now in response the server will send three records Back to Back wrapped in TLSRecord and every TLSRecord conains a messageType
  │◀─── Certificate ──────────────│         and in second record the server will send the certificate and they certificate oontains server's public key and other root certificaet one more important thing to remember that every ertificate has a chain of certficates
  │◀─── ServerHelloDone ──────────│         after this server will send another record of serverHelloDone saying that it's done now it's client time to send messages
  │──── ClientKeyExchange ───────▶│        before moving on please see that how the struct(interface) of these ClientHello, ServerHello, and LTS record is looks, i have metioned these above so readers won't be confused
  │──── ChangeCipherSpec ────────▶│
  │──── Finished ────────────────▶│
  │◀─── ChangeCipherSpec ─────────│
  │◀─── Finished ─────────────────│ -->

// The TLS record content types are:
// 0x14 → ChangeCipherSpec  (its own type)
// 0x15 → Alert
// 0x16 → Handshake
// 0x17 → ApplicationData
// Only 0x16 records contain a HandshakeMessage wrapper inside


Before understanding message TYPES, first understand HOW TLS sends Message Records. 
<!-- TLSRecord
    └── HandshakeMessage
            └── ClientHello (actual body) -->
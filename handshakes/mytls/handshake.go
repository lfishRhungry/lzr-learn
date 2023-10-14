package mytls

import (
	"bytes"
	"encoding/binary"
	"fmt"

	tls "github.com/refraction-networking/utls"
	"github.com/stanford-esrg/lzr"
)

// init a template of ClientHello with fixed info except timestamp
var clienHelloTemplate []byte

func init() {

	//modifying based on ClientHello of Chrome102 a
	spec := &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.GREASE_PLACEHOLDER,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			//!NOTE
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "pop3", "imap", "ftp"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
				tls.PskModeDHE,
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
				tls.CertCompressionBrotli,
			}},
			&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	// But we do not know hostname from an IP address, so...
	tClient := tls.UClient(nil, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)
	err := tClient.ApplyPreset(spec)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = tClient.BuildHandshakeState()
	if err != nil {
		fmt.Println(err)
		return
	}

	//Construct full TLS ClientHello data for tcp payload
	var b [2]byte
	l := uint16(len(tClient.HandshakeState.Hello.Raw))
	binary.BigEndian.PutUint16(b[0:2], l)
	clienHelloTemplate = append( //Need to wrap Handshake payload with TLS Record Layer
		[]byte{
			0x16,       //Content Type: Handshake (22)
			0x03, 0x01, //Version: TLS 1.0 (0x0301)
			b[0], b[1], //Length
		},
		tClient.HandshakeState.Hello.Raw...)

	//Inject '\r\n' to random of ClientHello manually.
	//this make http1.1 verified by http response for bad request
	clienHelloTemplate[0x0f] = 0x0d
	clienHelloTemplate[0x10] = 0x0a
}

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {

	data := bytes.Clone(clienHelloTemplate)

	return data
}

func (h *HandshakeMod) Verify(data string) string {
	if len(data) < 10 {
		return ""
	}

	//exposed by response to Bad request
	if data[0:4] == "HTTP" {
		return "http"
	}

	ret := ""
	datab := []byte(data)

	//check if TLS simply
	//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
	// Record Type Values       dec      hex
	// -------------------------------------
	// CHANGE_CIPHER_SPEC        20     0x14
	// ALERT                     21     0x15
	// HANDSHAKE                 22     0x16
	// APPLICATION_DATA          23     0x17
	if bytes.Equal(datab[0:1], []byte{0x16}) ||
		bytes.Equal(datab[0:1], []byte{0x14}) ||
		bytes.Equal(datab[0:1], []byte{0x15}) ||
		bytes.Equal(datab[0:1], []byte{0x17}) {
		ret = "tls"
	} else {
		return ret
	}

	//check TLS Version
	//Version Values            dec     hex
	// -------------------------------------
	// SSL 3.0                   3,0  0x0300
	// TLS 1.0                   3,1  0x0301
	// TLS 1.1                   3,2  0x0302
	// TLS 1.2                   3,3  0x0303
	// TLS 1.3                   3,4  0x0304
	if bytes.Contains(datab,
		[]byte{
			0x00, 0x2b, //Extension Type: supported_versions
			0x00, 0x02, //Length: 2
			0x03, 0x04, //TLS1.3
		}) {
		ret = "tls1.3"
		//ALPN extension is encrypted in ServerHello of tls1.3
		return ret
	} else if bytes.Equal(datab[1:3],
		[]byte{
			0x03, 0x03, //Record Layer Vesion: TLS1.2
		}) {
		ret = "tls1.2"
	} else if bytes.Equal(datab[1:3],
		[]byte{
			0x03, 0x02, //Record Layer Vesion: TLS1.1
		}) {
		ret = "tls1.1"
	} else if bytes.Equal(datab[1:3],
		[]byte{
			0x03, 0x01, //Record Layer Vesion: TLS1.0
		}) {
		ret = "tls1.0"
	} else if bytes.Equal(datab[1:3],
		[]byte{
			0x03, 0x00, //Record Layer Vesion: SSL3.0
		}) {
		ret = "ssl3.0"
	} else {
		//maybe not tls...
		return ret
	}

	//check application protocol over tls by Extension: ALPN
	if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x0b, //Length: 11
			0x00, 0x09, //ALPN Extension Length: 9
			0x08,                                           //ALPN string length: 8
			0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, //ALPN Next Protocol: http/1.1
		}) {
		ret = "https"
	} else if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x05, //Length: 5
			0x00, 0x03, //ALPN Extension Length: 3
			0x02,       //ALPN string length: 2
			0x68, 0x32, //ALPN Next Protocol: h2
		}) {
		ret = "http2"
	} else if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x06, //Length: 6
			0x00, 0x04, //ALPN Extension Length: 4
			0x03,             //ALPN string length: 3
			0x68, 0x32, 0x63, //ALPN Next Protocol: h2c
		}) {
		ret = "http2tcp"
	} else if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x07, //Length: 7
			0x00, 0x05, //ALPN Extension Length: 5
			0x04,                   //ALPN string length: 4
			0x70, 0x6f, 0x70, 0x33, //ALPN Next Protocol: pop3
		}) {
		ret = "pop3s"
	} else if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x07, //Length: 7
			0x00, 0x05, //ALPN Extension Length: 5
			0x04,                   //ALPN string length: 4
			0x69, 0x6d, 0x6d, 0x70, //ALPN Next Protocol: imap
		}) {
		ret = "imaps"
	} else if bytes.Contains(datab,
		[]byte{
			0x00, 0x10, //Extension Type: ALPN
			0x00, 0x06, //Length: 6
			0x00, 0x04, //ALPN Extension Length: 4
			0x03,             //ALPN string length: 3
			0x66, 0x74, 0x70, //ALPN Next Protocol: ftp
		}) {
		ret = "ftps"
	}

	// return ""
	// datab := []byte(data)
	// fmt.Printf("ServerHello len : %d\n", len(datab))
	// fmt.Printf("ServerHello data: %x\n", datab)
	return ret
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("mytls", &h)
}

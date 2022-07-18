package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emmansun/gmsm/zuc"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/gmsm/sm2"
	"github.com/pedroalbanese/gmsm/sm3"
	"github.com/pedroalbanese/gmsm/sm4"
	"github.com/pedroalbanese/gmsm/x509"
	"github.com/pedroalbanese/gmtls"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/randomart"
	"github.com/pedroalbanese/shred"
)

const Version = "1.2.1"

var (
	bit     = flag.Int("bits", 128, "Bit-length. (for DERIVE, PBKDF2 and RAND)")
	check   = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	crypt   = flag.String("crypt", "", "Encrypt/Decrypt with SM4 symmetric block cipher.")
	del     = flag.String("shred", "", "Files/Path/Wildcard to apply data sanitization method.")
	gen     = flag.Bool("keygen", false, "Generate asymmetric EC-SM2 keypair.")
	hexenc  = flag.String("hex", "", "Encode/Decode [e|d] binary string to hex format and vice-versa.")
	info    = flag.String("info", "", "Associated data, additional info. (for HKDF and AEAD encryption)")
	iter    = flag.Int("iter", 1, "Iterations. (for PBKDF2 and SHRED commands)")
	kdf     = flag.Bool("hkdf", false, "HMAC-based key derivation function.")
	key     = flag.String("key", "", "Private/Public key, Secret key or Password.")
	mac     = flag.String("mac", "", "Compute Cipher-based/Hash-based message authentication code.")
	mode    = flag.String("mode", "GCM", "Mode of operation: GCM, CTR or OFB.")
	pbkdf   = flag.Bool("pbkdf2", false, "Password-based key derivation function.")
	pkeyutl = flag.String("pkeyutl", "", "DERIVE shared secret, ENCRYPT/DECRYPT with asymmetric algorithm.")
	public  = flag.String("pub", "", "Remote's side public key/remote's side public IP/local port.")
	random  = flag.Bool("rand", false, "Generate random cryptographic key.")
	rec     = flag.Bool("recursive", false, "Process directories recursively.")
	salt    = flag.String("salt", "", "Salt. (for PBKDF2 and HKDF commands)")
	sig     = flag.Bool("sign", false, "Sign with PrivateKey.")
	sign    = flag.String("signature", "", "Input signature. (for verification only)")
	target  = flag.String("digest", "", "Target file/wildcard to generate hashsum list. ('-' for STDIN)")
	tcpip   = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [dump|send|ip|listen|dial]")
	vector  = flag.String("iv", "", "Initialization vector. (for symmetric encryption)")
	verify  = flag.Bool("verify", false, "Verify with PublicKey.")
	version = flag.Bool("version", false, "Print version information.")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *sm2.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

func handleConnection(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *version {
		fmt.Println(Version)
		return
	}

	if *random == true && (*bit == 256 || *bit == 184 || *bit == 128 || *bit == 64) {
		var key []byte
		var err error
		key = make([]byte, *bit/8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	}

	if *hexenc == "e" || *hexenc == "enc" || *hexenc == "encode" {
		b, err := ioutil.ReadAll(os.Stdin)
		if len(b) == 0 {
			os.Exit(0)
		}
		if err != nil {
			log.Fatal(err)
		}
		o := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(o, b)
		os.Stdout.Write(o)
		os.Exit(0)
	}

	if *hexenc == "d" || *hexenc == "dec" || *hexenc == "decode" {
		var err error
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		if len(b) == 0 {
			os.Exit(0)
		}
		if len(b) < 2 {
			os.Exit(0)
		}
		if (len(b)%2 != 0) || (err != nil) {
			log.Fatal(err)
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(o, []byte(b))
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	}

	if *tcpip == "dump" || *tcpip == "send" || *tcpip == "listen" || *tcpip == "dial" {
		priv, err := sm2.GenerateKey(nil)
		if err != nil {
			log.Fatal(err)
		}
		privPem, err := x509.WritePrivateKeyToPem(priv, nil)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, _ := priv.Public().(*sm2.PublicKey)
		pubkeyPem, err := x509.WritePublicKeyToPem(pubKey)
		privKey, err := x509.ReadPrivateKeyFromPem(privPem, nil)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err = x509.ReadPublicKeyFromPem(pubkeyPem)
		if err != nil {
			log.Fatal(err)
		}
		templateReq := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test"},
			},
		}
		reqPem, err := x509.CreateCertificateRequestToPem(&templateReq, privKey)
		if err != nil {
			log.Fatal(err)
		}
		req, err := x509.ReadCertificateRequestFromPem(reqPem)
		if err != nil {
			log.Fatal(err)
		}
		err = req.CheckSignature()
		if err != nil {
			log.Fatalf("Request CheckSignature error:%v", err)
		} else {
			fmt.Printf("CheckSignature ok\n")
		}

		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()

		extraExtensionData := []byte("extra extension")
		template := x509.Certificate{
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName: ip.String(),
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: *key,
					},
				},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

			BasicConstraintsValid: true,
			IsCA:                  true,

			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

			PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
			},
		}

		pripem, err := x509.WritePrivateKeyToPem(priv, nil)
		if err != nil {
			log.Fatal(err)
		}

		pubKey, _ = priv.Public().(*sm2.PublicKey)
		certpem, err := x509.CreateCertificateToPem(&template, &template, pubKey, privKey)
		if err != nil {
			log.Fatal("failed to create cert file")
		}

		if *tcpip == "dump" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}
			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, ClientAuth: gmtls.RequireAnyClientCert}
			config.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := gmtls.Listen("tcp", ":"+port, &config)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("Server(TLS) up and listening on port " + port)

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				go handleConnection(conn)

				var buf bytes.Buffer
				io.Copy(&buf, conn)
				text := strings.TrimSuffix(string(buf.Bytes()), "\n")
				fmt.Println(text)
				os.Exit(0)
			}
		}

		if *tcpip == "listen" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}
			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, ClientAuth: gmtls.RequireAnyClientCert}
			config.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := gmtls.Listen("tcp", ":"+port, &config)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			defer ln.Close()

			fmt.Println("Connection accepted")

			go handleConnection(conn)
			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Received: ", string(message))

				newmessage := strings.ToUpper(message)
				conn.Write([]byte(newmessage + "\n"))
			}
		}

		if *tcpip == "send" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			log.Printf("Connecting to %s\n", ipport)

			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, InsecureSkipVerify: true}
			conn, err := gmtls.Dial("tcp", ipport, &config)

			if err != nil {
				log.Fatal(err)
			}

			buf := bytes.NewBuffer(nil)
			scanner := os.Stdin
			io.Copy(buf, scanner)

			text := string(buf.Bytes())
			fmt.Fprintf(conn, text)

			defer conn.Close()

			log.Printf("Connection established between %s and localhost.\n", conn.RemoteAddr().String())
			os.Exit(0)
		}

		if *tcpip == "dial" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, InsecureSkipVerify: true}
			conn, err := gmtls.Dial("tcp", ipport, &config)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer Name: %s\n", cert.Issuer)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
				fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
				fmt.Printf("IP Address: %s \n", cert.IPAddresses)
			}
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
	}

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}

	if *crypt == "eea256" || *crypt == "zuc256" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 23)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt == "eea128" || *crypt == "eea3" || *crypt == "zuc128" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 16)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *mac == "eia256" || *mac == "zuc256" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var err error
		if keyHex == "" {
			keyRaw, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 32 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce, _ = hex.DecodeString("0000000000000000000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc.NewHash256(keyRaw, nonce, *bit/8)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		io.Copy(h, os.Stdin)
		var verify bool
		if *sign != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sign {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("%x\n", h.Sum(nil))
		os.Exit(0)
	}

	if *mac == "eia128" || *mac == "eia3" || *mac == "zuc128" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var err error
		if keyHex == "" {
			keyRaw, _ = hex.DecodeString("00000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 16 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce, _ = hex.DecodeString("00000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc.NewHash(keyRaw, nonce)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		io.Copy(h, os.Stdin)
		var verify bool
		if *sign != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sign {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("%x\n", h.Sum(nil))
		os.Exit(0)
	}

	if *crypt == "enc" && *mode == "GCM" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 128/8 {
				log.Fatal(err)
			}
		}

		ciph, err := sm4.NewCipher(key)
		aead, err := cipher.NewGCM(ciph)
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, nil)
		fmt.Printf("%s", out)

		os.Exit(0)
	}

	if *crypt == "dec" && *mode == "GCM" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 128/8 {
				log.Fatal(err)
			}
		}

		ciph, err := sm4.NewCipher(key)
		aead, err := cipher.NewGCM(ciph)
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)

		os.Exit(0)
	}

	if *crypt != "" && *mode != "GCM" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}
		ciph, err := sm4.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}
		var iv []byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			iv = make([]byte, 16)
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		var stream cipher.Stream
		if *mode == "CTR" || *mode == "ctr" {
			stream = cipher.NewCTR(ciph, iv)
		} else if *mode == "OFB" || *mode == "ofb" {
			stream = cipher.NewOFB(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *mac == "cmac" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 8, sm3.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
			if len(keyHex) != 128/8 {
				fmt.Println("Secret key must have 64-bit. (try \"-rand -short\")")
				os.Exit(1)
			}
		}
		c, _ := sm4.NewCipher([]byte(keyHex))
		h, _ := cmac.New(c)
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "hmac" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(sm3.New, key)
		if _, err = io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *target == "-" {
		h := sm3.New()
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *target != "" && *rec == false {
		files, err := filepath.Glob(*target)
		if err != nil {
			log.Fatal(err)
		}

		for _, match := range files {
			h := sm3.New()
			f, err := os.Open(match)
			if err != nil {
				log.Fatal(err)
			}
			file, err := os.Stat(match)
			if file.IsDir() {
			} else {
				if _, err := io.Copy(h, f); err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
			}
			f.Close()
		}
		os.Exit(0)
	}

	if *target != "" && *rec == true {
		err := filepath.Walk(filepath.Dir(*target),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if file.IsDir() {
				} else {
					filename := filepath.Base(path)
					pattern := filepath.Base(*target)
					matched, err := filepath.Match(pattern, filename)
					if err != nil {
						fmt.Println(err)
					}
					if matched {
						h := sm3.New()
						f, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						if _, err := io.Copy(h, f); err != nil {
							log.Fatal(err)
						}
						f.Close()
						fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		os.Exit(0)
	}

	if *check != "" {
		var file io.Reader
		var err error
		if *check == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string

		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}

		var exit int
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")

			if strings.Contains(string(eachline), " *") {

				h := sm3.New()

				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)
					f.Close()

					if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						fmt.Println(lines[1]+"\t", "OK")
					} else {
						fmt.Println(lines[1]+"\t", "FAILED")
						exit = 1
					}
				} else {
					fmt.Println(lines[1]+"\t", "Not found!")
					exit = 1
				}
			}
		}
		os.Exit(exit)
	}

	if *gen {
		var err error
		var prvRaw []byte
		var priv *sm2.PrivateKey
		if *key != "" && *pbkdf == false {
			priv, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else if *key != "" && *pbkdf {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, sm3.New)
			priv, err = ReadPrivateKeyFromHex(hex.EncodeToString(prvRaw))
			if err != nil {
				log.Fatal(err)
			}
		} else {
			priv, err = sm2.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
		}

		pub := &priv.PublicKey

		fmt.Println("Private= " + WritePrivateKeyToHex(priv))
		fmt.Println("Public= " + WritePublicKeyToHex(pub))
		os.Exit(0)
	}

	if *pkeyutl == "derive_a" {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}

		var split []string
		var ra []byte
		var rb []byte
		if *info != "" {
			info := *info
			split = strings.Split(info, ";")
			if len(split) < 2 {
				fmt.Println("Derivation needs two salts separated by semicolon.")
				os.Exit(2)
			}

			ra = sm3.Sm3Sum([]byte(split[0]))
			rb = sm3.Sm3Sum([]byte(split[1]))
		}

		k1, S1, Sa, err := sm2.KeyExchangeA(*bit/8, ra, rb, private, public, private, public)
		fmt.Printf("K1= %x\n", k1)
		fmt.Printf("S1= %x\n", S1)
		fmt.Printf("Sa= %x\n", Sa)
		os.Exit(0)

	}

	if *pkeyutl == "derive_b" {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}

		var split []string
		var ra []byte
		var rb []byte
		if *info != "" {
			info := *info
			split = strings.Split(info, ";")
			if len(split) < 2 {
				fmt.Println("Derivation needs two salts separated by semicolon.")
				os.Exit(2)
			}
			ra = sm3.Sm3Sum([]byte(split[0]))
			rb = sm3.Sm3Sum([]byte(split[1]))
		}

		k2, Sb, S2, err := sm2.KeyExchangeB(*bit/8, ra, rb, private, public, private, public)
		fmt.Printf("K2= %x\n", k2)
		fmt.Printf("Sb= %x\n", Sb)
		fmt.Printf("S2= %x\n", S2)
		os.Exit(0)
	}

	if *pkeyutl == "derive" {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}

		b, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())
		shared := sm3.Sm3Sum(b.Bytes())
		fmt.Printf("Shared= %x\n", shared[0:*bit/8])
		os.Exit(0)
	}

	if *pkeyutl == "enc" || *pkeyutl == "encrypt" {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := pub.EncryptAsn1([]byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
		os.Exit(0)
	}

	if *pkeyutl == "dec" || *pkeyutl == "decrypt" {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str, _ := hex.DecodeString(string(scanner))
		plaintxt, err := priv.DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
		os.Exit(0)
	}

	if *sig {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		sign, err := priv.Sign(rand.Reader, []byte(scanner), nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", sign)
		os.Exit(0)
	}

	if *verify {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		signature, _ := hex.DecodeString(*sign)
		isok := pub.Verify([]byte(scanner), []byte(signature))
		if isok == true {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *del != "" {
		shredder := shred.Shredder{}
		shredconf := shred.NewShredderConf(&shredder, shred.WriteRand|shred.WriteZeros, *iter, true)
		matches, err := filepath.Glob(*del)
		if err != nil {
			panic(err)
		}

		for _, match := range matches {
			err := shredconf.ShredDir(match)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}

	if *pbkdf == true && *crypt == "" && *mac == "" && (*bit == 256 || *bit == 184 || *bit == 128 || *bit == 64) {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *bit/8, sm3.New)
		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *kdf {
		keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		keySlice := string(keyRaw[:])
		fmt.Println(hex.EncodeToString([]byte(keySlice)[:*bit/8]))
		os.Exit(0)
	}

	if *key != "" && *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else if *key != "" && *key != "-" {
		fmt.Println(randomart.FromString(*key))
	}
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	var h func() hash.Hash
	g := func() hash.Hash {
		return sm3.New()
	}
	h = g
	hkdf := hkdf.New(h, master, salt, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf, key)
	var result [128]byte
	copy(result[:], key)
	return result, err
}

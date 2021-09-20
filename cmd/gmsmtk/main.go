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
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/gmsm/sm2"
	"github.com/pedroalbanese/gmsm/sm3"
	"github.com/pedroalbanese/gmsm/sm4"
	"github.com/pedroalbanese/gmsm/x509"
	"github.com/pedroalbanese/gmsmtk"
	"github.com/pedroalbanese/gmtls"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/randomart"
	"github.com/pedroalbanese/shred"
)

var (
	bit     = flag.Int("bits", 128, "Bit-length. (for DERIVE, PBKDF2 and RAND)")
	check   = flag.String("check", "", "Check hashsum file. (- for STDIN)")
	crypt   = flag.String("crypt", "", "Encrypt/Decrypt with SM4 symmetric block cipher.")
	dec     = flag.Bool("sm2dec", false, "Decrypt with asymmetric EC-SM2 Privatekey.")
	del     = flag.String("shred", "", "Files/Path/Wildcard to apply data sanitization method.")
	derive  = flag.String("derive", "", "Derive shared secret key (SM2-ECDH) 128-bit default.")
	enc     = flag.Bool("sm2enc", false, "Encrypt with asymmetric EC-SM2 Publickey.")
	gen     = flag.Bool("keygen", false, "Generate asymmetric EC-SM2 keypair.")
	crt     = flag.Bool("crtgen", false, "Generate EC-SM2 key and certificate for TLS connection.")
	hexenc  = flag.String("hex", "", "Encode/Decode [e|d] binary string to hex format and vice-versa.")
	iter    = flag.Int("iter", 1, "Iterations. (for PBKDF2 and SHRED commands)")
	key     = flag.String("key", "", "Private/Public key, Secret key or Password.")
	mac     = flag.String("mac", "", "Compute Cipher-based/Hash-based message authentication code.")
	mode    = flag.String("mode", "GCM", "Mode of operation: GCM, CTR or OFB.")
	pbkdf   = flag.Bool("pbkdf2", false, "Password-based key derivation function.")
	public  = flag.String("pub", "", "Remote's side public key/remote's side public IP/PEM BLOCK.")
	random  = flag.Bool("rand", false, "Generate random cryptographic key.")
	rec     = flag.Bool("recursive", false, "Process directories recursively.")
	salt    = flag.String("salt", "", "Salt. (for PBKDF2)")
	sig     = flag.Bool("sign", false, "Sign with PrivateKey.")
	sign    = flag.String("signature", "", "Input signature. (for verification only)")
	target  = flag.String("digest", "", "Target file/wildcard to generate hashsum list. (- for STDIN)")
	tcpip   = flag.String("tcp", "", "Encrypted TCP/IP [dump|ip|send] Transfer Protocol.")
	verbose = flag.Bool("verbose", false, "Verbose mode. (for CHECK command)")
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
	log.Printf("Connection from %v closed.", c.RemoteAddr())
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *version {
		fmt.Println(gmsmtk.Version)
		return
	}

	if *random == true && (*bit == 256 || *bit == 128 || *bit == 64) {
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

	if *crt {
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

		name := *public
		var org string
		var country string
		if strings.Contains(name, ";") {
			split := strings.Split(name, ";")
			if len(split) < 2 {
				fmt.Println("PEM encoding needs two pub values separated by semicolon.")
				os.Exit(2)
			}
			if split[0] != "" {
				org = split[0]
			}
			country = split[1]
		} else {
			org = name
		}

		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()

		extraExtensionData := []byte("extra extension")
		template := x509.Certificate{
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   ip.String(),
				Organization: []string{org},
				Country:      []string{country},
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
		ioutil.WriteFile("key.pem", pripem, 0644)

		pubKey, _ = priv.Public().(*sm2.PublicKey)
		certpem, err := x509.CreateCertificateToPem(&template, &template, pubKey, privKey)
		if err != nil {
			log.Fatal("failed to create cert file")
		}
		ioutil.WriteFile("cert.crt", certpem, 0644)
		os.Exit(0)
	}

	if *tcpip == "dump" {
		cert, err := gmtls.LoadX509KeyPair("cert.crt", "key.pem")

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

	if *tcpip == "send" {
		cert, err := gmtls.LoadX509KeyPair("cert.crt", "key.pem")

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

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
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
		iv := make([]byte, 16)
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

					if *verbose {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
							fmt.Println(lines[1]+"\t", "OK")
						} else {
							fmt.Println(lines[1]+"\t", "FAILED")
						}
					} else {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						} else {
							os.Exit(1)
						}
					}
				} else {
					if *verbose {
						fmt.Println(lines[1]+"\t", "Not found!")
					} else {
						os.Exit(1)
					}
				}
			}
		}
		os.Exit(0)
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

	if *derive == "a" {
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
		if *salt != "" {
			salt := *salt
			split = strings.Split(salt, ";")
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

	if *derive == "b" {
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
		if *salt != "" {
			salt := *salt
			split = strings.Split(salt, ",")
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

	if *derive == "c" {
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

	if *enc {
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

	if *dec {
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

	if *pbkdf == true && *crypt == "" && *mac == "" && (*bit == 256 || *bit == 128 || *bit == 64) {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *bit/8, sm3.New)
		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *key != "" && *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else if *key != "" && *key != "-" {
		fmt.Println(randomart.FromString(*key))
	}
}

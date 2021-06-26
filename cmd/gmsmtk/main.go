package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/gmsm/sm2"
	"github.com/pedroalbanese/gmsm/sm3"
	"github.com/pedroalbanese/gmsm/sm4"
	"github.com/pedroalbanese/shred"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	check   = flag.String("check", "", "Check hashsum file.")
	ciphmac = flag.Bool("cmac", false, "Cipher-based message authentication code.")
	crypt   = flag.Bool("crypt", false, "Encrypt/Decrypt with symmetric cipher SM4.")
	dec     = flag.Bool("sm2dec", false, "Decrypt with asymmetric SM2 PrivateKey.")
	decode  = flag.Bool("decode", false, "Decode hex string to binary format.")
	del     = flag.String("shred", "", "Files/Path/Wildcard to apply data sanitization method.")
	digest  = flag.Bool("digest", false, "Compute single hashsum with SM3.")
	enc     = flag.Bool("sm2enc", false, "Encrypt with asymmetric SM2 Publickey.")
	encode  = flag.Bool("encode", false, "Encode binary string to hex format.")
	gen     = flag.Bool("keygen", false, "Generate asymmetric key pair.")
	iter    = flag.Int("iter", 1, "Iterations. (for PBKDF2 and SHRED commands)")
	key     = flag.String("key", "", "Private/Public key, Secret key or Password.")
	mac     = flag.Bool("hmac", false, "Hash-based message authentication code.")
	mode    = flag.String("mode", "CTR", "Mode of operation: CTR or OFB.")
	pbkdf   = flag.Bool("pbkdf2", false, "Password-based key derivation function.")
	random  = flag.Bool("rand", false, "Generate random cryptographic key.")
	rec     = flag.Bool("recursive", false, "Process directories recursively.")
	salt    = flag.String("salt", "", "Salt. (for PBKDF2)")
	short   = flag.Bool("short", false, "Generate 64-bit key. (for PBKDF2 and RAND commands)")
	sig     = flag.Bool("sign", false, "Sign with PrivateKey.")
	sign    = flag.String("signature", "", "Input signature. (for verification only)")
	target  = flag.String("hashsum", "", "Target file/wildcard to generate hashsum list.")
	verbose = flag.Bool("verbose", false, "Verbose mode. (for CHECK command)")
	verify  = flag.Bool("verify", false, "Verify with PublicKey.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "GMSM Cipher Suite - Chinese National Standard Toolkit")
		fmt.Fprintln(os.Stderr, "Copyright (c) 2020-2021 Pedro Albanese. All rights reserved.\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *random == true && *short == false {
		var key []byte
		var err error
		key = make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	}

	if *random == true && *short == true {
		var key []byte
		var err error
		key = make([]byte, 8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	}

	if *encode == true {
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
	}

	if *decode == true {
		b, err := ioutil.ReadAll(os.Stdin)
		if len(b) < 2 {
			os.Exit(0)
		}
		if (len(b)%2 != 0) || (err != nil) {
			log.Fatal(err)
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(o, b)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
	}

	if *crypt == true {
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

	if *digest == true && *target == "" {
		h := sm3.New()
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *ciphmac == true {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
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

	if *mac == true {
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

	if *pbkdf == true && *crypt == false && *mac == false && *short == false {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *crypt == false && *mac == false && *short == true {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 8, sm3.New)
		fmt.Println(hex.EncodeToString(prvRaw))
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
	}

	if *check != "" {
		file, err := os.Open(*check)

		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string

		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}

		file.Close()

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
	}

	if *gen == true {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		pub := &priv.PublicKey

		fmt.Println("Private= " + WritePrivateKeyToHex(priv))
		fmt.Println("Public= " + WritePublicKeyToHex(pub))
	}

	if *enc {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		ciphertxt, err := pub.EncryptAsn1([]byte(line), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
	}

	if *dec {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		str, _ := hex.DecodeString(string(line))
		plaintxt, err := priv.DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
	}

	if *sig {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		sign, err := priv.Sign(rand.Reader, []byte(line), nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", sign)
	}

	if *verify {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		signature, _ := hex.DecodeString(*sign)
		isok := pub.Verify([]byte(line), []byte(signature))
		if isok == true {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(1)
		}
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
	}
}

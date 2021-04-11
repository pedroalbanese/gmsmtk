//go:generate goversioninfo -manifest=testdata/resource/goversioninfo.exe.manifest
package main
import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/pedroalbanese/gmcrypto/sm3"
	"github.com/pedroalbanese/gmcrypto/sm4"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

	var check = flag.String("check", "", "Check hashsum file.")
	var crypt = flag.Bool("crypt", false, "Encrypt/Decrypt with symmetric cipher SM4.")
	var digest = flag.Bool("digest", false, "Compute single hashsum with SM3.")
	var iter = flag.Int("iter", 1024, "Iterations. (for PBKDF2)")
	var key = flag.String("key", "", "Secret key/Password.")
	var mac = flag.Bool("hmac", false, "Hash-based message authentication code.")
	var pbkdf = flag.Bool("pbkdf2", false, "PBKDF2.")
	var random = flag.Bool("rand", false, "Generate random 128-bit cryptographic key.")
	var recursive = flag.Bool("rec", false, "Process directories recursively.")
	var salt = flag.String("salt", "", "Salt. (for PBKDF2)")
	var target = flag.String("hashsum", "", "Target file/wildcard to generate hashsum list.")
	var verbose = flag.Bool("verb", false, "Verbose mode. (for CHECK command)")

func main() {
    flag.Parse()

        if (len(os.Args) < 2) {
	fmt.Fprintln(os.Stderr,"GMSM Chinese National Standard Toolkit - ALBANESE Lab (c) 2020-2021\n")
	fmt.Fprintln(os.Stderr,"Usage of",os.Args[0]+":")
        flag.PrintDefaults()
        os.Exit(0)
        }

	if *random == true {
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

        if *pbkdf == true && *crypt == false && *mac == false {
	prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
	fmt.Println(hex.EncodeToString(prvRaw))
	os.Exit(0)
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
	stream := cipher.NewCTR(ciph, iv)
	buf := make([]byte, 32*1<<10)
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


        if *target != "" && *recursive == false {
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
        if _, err := io.Copy(h, f); err != nil {
            log.Fatal(err)
        }
    	fmt.Println(hex.EncodeToString(h.Sum(nil)), "*" + f.Name())
	}
	}


	if *target != "" && *recursive == true {
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
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*" + f.Name())
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
		
		if *verbose {
			if hex.EncodeToString(h.Sum(nil)) == lines[0] {
				fmt.Println(lines[1] + "\t", "OK")
			} else {
				fmt.Println(lines[1] + "\t", "FAILED")
			}
		} else {
			if hex.EncodeToString(h.Sum(nil)) == lines[0] {
			} else {
				os.Exit(1)
			}
		}
	} else {
		if *verbose {
			fmt.Println(lines[1] + "\t", "Not found!")
		} else {
			os.Exit(1)	
		}	
	}
	}
	}

	}
}

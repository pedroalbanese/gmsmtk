// SPDX-License-Identifier: ISC
//
// Copyright (c) 2026 Pedro F. Albanese <pedroalbanese@hotmail.com>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/gmsm/zuc"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/gopass"
	"github.com/pedroalbanese/randomart"
)

const (
	Version     = "1.2.4"
	VersionDate = "08 Nov 2026"
)

var (
	alg       = flag.String("algorithm", "SM2", "Algorithm: SM2, SM9SIGN, SM9ENCRYPT.")
	cacert    = flag.String("cacert", "", "CA certificate path. (for TLCP Protocol)")
	cakey     = flag.String("cakey", "", "CA private key. (for TLCP Protocol)")
	cert      = flag.String("cert", "", "Certificate path.")
	check     = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	cph       = flag.String("cipher", "sm4", "Symmetric cipher: sm4, zuc128, zuc256.")
	crypt     = flag.String("crypt", "", "Bulk Encryption with SM4/ZUC. [enc|dec]")
	digest    = flag.Bool("digest", false, "Generate hashsum list for the given file(s)/wildcard(s). ('-' for STDIN)")
	encode    = flag.String("hex", "", "Encode/Decode/Dump hex. [enc|dec|dump]")
	days      = flag.Int("days", 0, "Certificate validity (days).")
	hierarchy = flag.Uint("hid", 0x01, "Hierarchy Identifier (SM9).")
	id        = flag.String("id", "", "User Identifier (SM9).")
	id2       = flag.String("peerid", "", "Remote User Identifier (SM9 key exchange).")
	info      = flag.String("info", "", "Associated data / additional info.")
	isca      = flag.Bool("isca", false, "The requested CSR is for a Certificate Authority (CA).")
	iter      = flag.Int("iter", 1, "Iterations (PBKDF2).")
	kdf       = flag.Int("hkdf", 0, "HKDF output bit length (0 = off).")
	key       = flag.String("key", "", "Asymmetric/symmetric key or HMAC key.")
	length    = flag.Int("bits", 0, "Key length (bits).")
	mac       = flag.String("mac", "", "MAC: zuc128|zuc256|eia128|eia256|hmac|cmac.")
	master    = flag.String("master", "Master.pem", "Master key path (SM9 setup).")
	md        = flag.String("md", "sm3", "Message digest: sm3.")
	mode      = flag.String("mode", "GCM", "Mode: GCM, CBC, CTR, OFB, CFB.")
	pbkdf     = flag.Bool("pbkdf2", false, "Password-based key derivation function 2.")
	pkey      = flag.String("pkey", "", "Subcommands: keygen|certgen|req|x509|crl|check|validate|text|modulus|randomart|fingerprint|sign|verify|encrypt|decrypt|setup|wrapkey|unwrapkey|derivea|deriveb")
	prv       = flag.String("prv", "Private.pem", "Private key output path.")
	pub       = flag.String("pub", "Public.pem", "Public key output path.")
	pwd       = flag.String("pass", "", "Password (PEM encryption).")
	pwd2      = flag.String("passout", "", "User Password (SM9 user key PEM encryption).")
	random    = flag.Int("rand", 0, "Generate random key (bits: 64|128|256|512).")
	recursive = flag.Bool("recursive", false, "Process directories recursively.")
	root      = flag.String("root", "", "Root CA Certificate path.")
	crl       = flag.String("crl", "", "Certificate Revocation List path.")
	salt      = flag.String("salt", "", "Salt (PBKDF2 / HKDF).")
	sig       = flag.String("signature", "", "Input signature (verification).")
	subj      = flag.String("subj", "", "Subject: \"/CN=/OU=/O=/ST=/L=/C=/emailAddress=\".")
	tcpip     = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [server|client|ip]")
	iport     = flag.String("ipport", "", "Local Port/remote side IP:Port.")
	vector    = flag.String("iv", "", "Initialization Vector.")
	version   = flag.Bool("version", false, "Print version info.")
)

var (
	name, number, country, province, locality, organization, organizationunit, street, email, postalcode string
)

// ===========================================================================
// PEM Encryption — SM4 only
// ===========================================================================

type PEMCipher int

const (
	_ PEMCipher = iota
	PEMCipherSM4
)

type rfc1423Algo struct {
	cipher     PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
}

var rfc1423Algos = []rfc1423Algo{{
	cipher:     PEMCipherSM4,
	name:       "SM4-CBC",
	cipherFunc: sm4.NewCipher,
	keySize:    16,
	blockSize:  sm4.BlockSize,
}}

func (c rfc1423Algo) deriveKey(password, salt []byte) []byte {
	h := md5.New()
	out := make([]byte, c.keySize)
	var digest []byte
	for i := 0; i < len(out); i += len(digest) {
		h.Reset()
		h.Write(digest)
		h.Write(password)
		h.Write(salt)
		digest = h.Sum(digest[:0])
		copy(out[i:], digest)
	}
	return out
}

func IsEncryptedPEMBlock(b *pem.Block) bool {
	_, ok := b.Headers["DEK-Info"]
	return ok
}

var IncorrectPasswordError = errors.New("x509: decryption password incorrect")

func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("x509: no DEK-Info header in block")
	}
	idx := strings.Index(dek, ",")
	if idx == -1 {
		return nil, errors.New("x509: malformed DEK-Info header")
	}
	mode, hexIV := dek[:idx], dek[idx+1:]
	ciph := cipherByName(mode)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}
	if len(iv) != ciph.blockSize {
		return nil, errors.New("x509: incorrect IV size")
	}
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}
	if len(b.Bytes)%block.BlockSize() != 0 {
		return nil, errors.New("x509: encrypted PEM data is not a multiple of the block size")
	}
	data := make([]byte, len(b.Bytes))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(data, b.Bytes)
	dlen := len(data)
	if dlen == 0 || dlen%ciph.blockSize != 0 {
		return nil, errors.New("x509: invalid padding")
	}
	last := int(data[dlen-1])
	if dlen < last || last == 0 || last > ciph.blockSize {
		return nil, IncorrectPasswordError
	}
	for _, val := range data[dlen-last:] {
		if int(val) != last {
			return nil, IncorrectPasswordError
		}
	}
	return data[:dlen-last], nil
}

func EncryptPEMBlock(randReader io.Reader, blockType string, data, password []byte, alg PEMCipher) (*pem.Block, error) {
	ciph := cipherByKey(alg)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(randReader, iv); err != nil {
		return nil, errors.New("x509: cannot generate IV: " + err.Error())
	}
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)
	copy(encrypted, data)
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}
	enc.CryptBlocks(encrypted, encrypted)
	return &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  ciph.name + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}, nil
}

func cipherByName(name string) *rfc1423Algo {
	for i := range rfc1423Algos {
		if rfc1423Algos[i].name == name {
			return &rfc1423Algos[i]
		}
	}
	return nil
}

func cipherByKey(k PEMCipher) *rfc1423Algo {
	for i := range rfc1423Algos {
		if rfc1423Algos[i].cipher == k {
			return &rfc1423Algos[i]
		}
	}
	return nil
}

// ===========================================================================
// Helpers
// ===========================================================================

func handleConnectionTLCP(c net.Conn) {
	log.Printf("Client(TLCP) %v connected via secure channel.", c.RemoteAddr())
}

func stdinIsPipeOrFile() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	m := fi.Mode()
	return m&os.ModeCharDevice == 0 || m.IsRegular()
}

func openInput() io.Reader {
	if stdinIsPipeOrFile() {
		return os.Stdin
	}
	if flag.Arg(0) != "" {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		return f
	}
	log.Fatal("no input: pipe data via STDIN or pass a file as the first positional argument")
	return nil
}

func readPassword(masked bool) string {
	var pw []byte
	var err error
	if masked {
		pw, err = gopass.GetPasswdMasked()
	} else {
		pw, err = gopass.GetPasswd()
	}
	if err != nil {
		log.Fatal(err)
	}
	return string(pw)
}

func inputName() string {
	if stdinIsPipeOrFile() {
		return "(stdin)"
	}
	if flag.Arg(0) != "" {
		return flag.Arg(0)
	}
	return "(stdin)"
}

func parseSubjectString(subject string) (name, number, country, province, locality, organization, organizationunit, street, email, postalcode string, err error) {
	parts := strings.Split(subject, "/")
	if len(parts) < 6 || len(parts) > 10 {
		return "", "", "", "", "", "", "", "", "", "", errors.New("invalid subject string format")
	}
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "C":
			country = kv[1]
		case "ST":
			province = kv[1]
		case "L":
			locality = kv[1]
		case "O":
			organization = kv[1]
		case "OU":
			organizationunit = kv[1]
		case "CN":
			name = kv[1]
		case "emailAddress":
			email = kv[1]
		case "postalCode":
			postalcode = kv[1]
		case "STREET":
			street = kv[1]
		case "serialNumber":
			number = kv[1]
		}
	}
	return
}

func calculateFingerprint(k []byte) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:])
}

// computeSKID derives a Subject Key Identifier from a public key using SM3
// over the SPKI's subjectPublicKey BIT STRING. Returns the first 20 bytes
// (RFC 7093 truncated hash — appropriate for SM2/SM3).
func computeSKID(pub interface{}) []byte {
	der, err := smx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil
	}
	sum := sm3.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:20]
}

// SplitSubN splits s into chunks of n characters.
func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}
	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}
	return subs
}

// split breaks s into pieces of the given size.
func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]
	}
	return ss
}

// formatHexPoints prints bytes as colon-separated hex, wrapped at
// ~45 characters, indented with 4 spaces — same style as edgetk.
func formatHexPoints(b []byte) string {
	s := hex.EncodeToString(b)
	splitz := SplitSubN(s, 2)
	chunks := split(strings.Trim(fmt.Sprint(splitz), "[]"), 45)
	var out strings.Builder
	for _, chunk := range chunks {
		out.WriteString("    ")
		out.WriteString(strings.ReplaceAll(chunk, " ", ":"))
		out.WriteString("\n")
	}
	return out.String()
}

// indentedHexColonLower formats bytes as ':'-separated lowercase hex, breaking
// every `perLine` bytes, with the given line prefix.
func indentedHexColonLower(b []byte, indent string, perLine int) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += perLine {
		end := i + perLine
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(indent)
		for j := i; j < end; j++ {
			if j > i {
				sb.WriteByte(':')
			}
			sb.WriteString(hex.EncodeToString(b[j : j+1]))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// indentedHexColonTrail formats bytes as lowercase hex with ':' between bytes
// AND ':' at the end of each intermediate line — openssl x509 -text style.
func indentedHexColonTrail(b []byte, indent string, perLine int) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += perLine {
		end := i + perLine
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(indent)
		for j := i; j < end; j++ {
			if j > i {
				sb.WriteByte(':')
			}
			sb.WriteString(hex.EncodeToString(b[j : j+1]))
		}
		if end < len(b) {
			sb.WriteByte(':')
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// hexColonLower returns the slice as lowercase ':'-separated hex (single line).
func hexColonLower(b []byte) string {
	var parts []string
	for _, v := range b {
		parts = append(parts, hex.EncodeToString([]byte{v}))
	}
	return strings.Join(parts, ":")
}

// reverseNameString converts pkix.Name into OpenSSL/edgetk order
// (C=...,ST=...,L=...,STREET=...,POSTALCODE=...,O=...,OU=...,CN=...,SERIALNUMBER=...).
func reverseNameString(n pkix.Name) string {
	order := []struct {
		key   string
		value []string
	}{
		{"C", n.Country},
		{"ST", n.Province},
		{"L", n.Locality},
		{"STREET", n.StreetAddress},
		{"POSTALCODE", n.PostalCode},
		{"O", n.Organization},
		{"OU", n.OrganizationalUnit},
		{"CN", []string{n.CommonName}},
		{"SERIALNUMBER", []string{n.SerialNumber}},
	}
	var parts []string
	for _, kv := range order {
		if len(kv.value) == 0 {
			continue
		}
		parts = append(parts, kv.key+"="+kv.value[0])
	}
	return strings.Join(parts, ",")
}

// printPubKeyXY prints EC public key X and Y points in edgetk/openssl style.
func printPubKeyXY(pub *ecdsa.PublicKey, indent string) {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	if n := len(xBytes); n < byteLen {
		xBytes = append(make([]byte, byteLen-n), xBytes...)
	}
	if n := len(yBytes); n < byteLen {
		yBytes = append(make([]byte, byteLen-n), yBytes...)
	}
	fmt.Printf("%sX:\n", indent)
	fmt.Print(indentedHexColonTrail(xBytes, indent+"    ", 15))
	fmt.Printf("%sY:\n", indent)
	fmt.Print(indentedHexColonTrail(yBytes, indent+"    ", 15))
	fmt.Printf("%sCurve: %s\n", indent, pub.Curve.Params().Name)
}

// loadPlainKeyPair reads cert and key files, decrypting the key PEM block
// when it carries DEK-Info. If no password was supplied it asks the user
// (via gopass) up to 3 times. Returns PEM bytes suitable for
// tlcp.X509KeyPair, which does not decrypt PEM itself.
func loadPlainKeyPair(certPath, keyPath, password string) ([]byte, []byte) {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		log.Fatalf("no PEM block in %s", keyPath)
	}
	if !IsEncryptedPEMBlock(block) {
		return certData, keyData
	}

	if password != "" {
		der, err := DecryptPEMBlock(block, []byte(password))
		if err != nil {
			log.Fatalf("cannot decrypt %s: %v (check -pass)", keyPath, err)
		}
		return certData, pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	}

	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Fprintf(os.Stderr, "Passphrase for %s: ", keyPath)
		pw, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}
		der, err := DecryptPEMBlock(block, pw)
		if err == nil {
			return certData, pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
		}
		fmt.Fprintf(os.Stderr, "attempt %d: %v\n", attempt, err)
	}
	log.Fatalf("cannot decrypt %s after 3 attempts", keyPath)
	return nil, nil
}

// ===========================================================================
// main
// ===========================================================================

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		printBanner()
		os.Exit(0)
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("GMSMTk v%s  %s\n", Version, VersionDate)
		return
	}

	// -rand
	if *random != 0 {
		if *random != 64 && *random != 128 && *random != 256 && *random != 512 {
			log.Fatal("RAND must have 64/128/256/512-bit.")
		}
		k := make([]byte, *random/8)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(k))
		os.Exit(0)
	}

	// -hex
	if *encode == "enc" || *encode == "encode" {
		b, _ := ioutil.ReadAll(openInput())
		if len(b) == 0 {
			os.Exit(0)
		}
		o := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(o, b)
		os.Stdout.Write(o)
		os.Exit(0)
	}
	if *encode == "dec" || *encode == "decode" {
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, openInput())
		b := strings.TrimRight(buf.String(), "\r\n")
		if len(b) < 2 {
			os.Exit(0)
		}
		if len(b)%2 != 0 {
			log.Fatal("invalid hex string: odd length")
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		if _, err := hex.Decode(o, []byte(b)); err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	}
	if *encode == "dump" {
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, openInput())
		b := strings.TrimRight(buf.String(), "\r\n")
		os.Stdout.WriteString(hex.Dump([]byte(b)))
		os.Exit(0)
	}

	// -digest (multi-file, wildcards, recursive) — gosttk-compatible
	if *digest {
		// No positional args → read STDIN.
		if len(flag.Args()) == 0 {
			h := sm3.New()
			io.Copy(h, os.Stdin)
			fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
			os.Exit(0)
		}

		// "-" as the only positional arg → read STDIN.
		if len(flag.Args()) == 1 && flag.Arg(0) == "-" {
			h := sm3.New()
			io.Copy(h, os.Stdin)
			fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
			os.Exit(0)
		}

		if !*recursive {
			// Non-recursive: expand wildcards and hash each file.
			for _, wildcard := range flag.Args() {
				var matches []string
				if strings.ContainsAny(wildcard, "*?[") {
					m, err := filepath.Glob(wildcard)
					if err != nil {
						log.Fatal(err)
					}
					matches = m
				} else {
					matches = []string{wildcard}
				}
				for _, match := range matches {
					f, err := os.Open(match)
					if err != nil {
						log.Fatal(err)
					}
					info, err := f.Stat()
					if err != nil {
						f.Close()
						log.Fatal(err)
					}
					if info.IsDir() {
						f.Close()
						continue
					}
					h := sm3.New()
					if _, err := io.Copy(h, f); err != nil {
						f.Close()
						log.Fatal(err)
					}
					f.Close()
					fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+filepath.Base(match))
				}
			}
			os.Exit(0)
		}

		// Recursive: for each wildcard, walk the parent directory and
		// match the basename pattern. Deduplicate by full path.
		seen := make(map[string]bool)
		for _, wildcard := range flag.Args() {
			base := filepath.Base(wildcard)
			rootDir := filepath.Dir(wildcard)
			err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				matched, err := filepath.Match(base, info.Name())
				if err != nil {
					return err
				}
				if !matched || seen[path] {
					return nil
				}
				seen[path] = true
				h := sm3.New()
				f, err := os.Open(path)
				if err != nil {
					log.Fatal(err)
				}
				if _, err := io.Copy(h, f); err != nil {
					f.Close()
					log.Fatal(err)
				}
				f.Close()
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+filepath.Base(path))
				return nil
			})
			if err != nil {
				log.Println(err)
			}
		}
		os.Exit(0)
	}

	if *check != "" {
		var r io.Reader
		var err error
		if *check == "-" {
			r = os.Stdin
		} else {
			r, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		sc := bufio.NewScanner(r)
		var exit int
		for sc.Scan() {
			line := sc.Text()
			parts := strings.Split(line, " *")
			if len(parts) != 2 {
				continue
			}
			h := sm3.New()
			f, err := os.Open(parts[1])
			if err != nil {
				fmt.Println(parts[1]+"\t", "Not found!")
				exit = 1
				continue
			}
			io.Copy(h, f)
			f.Close()
			if hex.EncodeToString(h.Sum(nil)) == parts[0] {
				fmt.Println(parts[1]+"\t", "OK")
			} else {
				fmt.Println(parts[1]+"\t", "FAILED")
				exit = 1
			}
		}
		os.Exit(exit)
	}

	// -mac
	if *mac == "hmac" {
		keyHex := *key
		var keyRaw []byte
		var err error
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		}
		keyRaw, err = hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(sm3.New, keyRaw)
		io.Copy(h, openInput())
		if *sig != "" {
			if hex.EncodeToString(h.Sum(nil)) != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}
	if *mac == "cmac" {
		keyHex := *key
		if len(keyHex) != 32 {
			log.Fatal("CMAC-SM4 requires a 16-byte key (32 hex chars)")
		}
		keyRaw, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		c, err := sm4.NewCipher(keyRaw)
		if err != nil {
			log.Fatal(err)
		}
		h, _ := cmac.New(c)
		io.Copy(h, openInput())
		if *sig != "" {
			if hex.EncodeToString(h.Sum(nil)) != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}
	if *mac == "zuc128" || *mac == "eia128" || *mac == "eia3" {
		keyHex := *key
		var keyRaw []byte
		var err error
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		}
		if keyHex == "" {
			keyRaw = make([]byte, 16)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 16 {
				log.Fatal("ZUC-128 requires a 16-byte key")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce = make([]byte, 16)
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc.NewHash(keyRaw, nonce)
		io.Copy(h, openInput())
		if *sig != "" {
			if hex.EncodeToString(h.Sum(nil)) != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}
	if *mac == "zuc256" || *mac == "eia256" {
		keyHex := *key
		var keyRaw []byte
		var err error
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		}
		if keyHex == "" {
			keyRaw = make([]byte, 32)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 32 {
				log.Fatal("ZUC-256 requires a 32-byte key")
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce = make([]byte, 23)
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		tagLen := *length / 8
		if tagLen == 0 {
			tagLen = 32
		}
		h, _ := zuc.NewHash256(keyRaw, nonce, tagLen)
		io.Copy(h, openInput())
		if *sig != "" {
			if hex.EncodeToString(h.Sum(nil)) != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	// -crypt
	if *crypt == "enc" || *crypt == "dec" {
		cipherName := strings.ToLower(*cph)

		// ZUC stream
		if cipherName == "zuc128" || cipherName == "eea128" || cipherName == "eea3" ||
			cipherName == "zuc256" || cipherName == "eea256" {
			keyLen := 16
			nonceLen := 16
			if cipherName == "zuc256" || cipherName == "eea256" {
				keyLen = 32
				nonceLen = 23
			}
			keyHex := *key
			var keyRaw []byte
			var err error
			if *pbkdf {
				keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, keyLen, sm3.New)
				keyHex = hex.EncodeToString(keyRaw)
			}
			if keyHex == "" {
				keyRaw = make([]byte, keyLen)
				io.ReadFull(rand.Reader, keyRaw)
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
			} else {
				keyRaw, err = hex.DecodeString(keyHex)
				if err != nil {
					log.Fatal(err)
				}
				if len(keyRaw) != keyLen {
					log.Fatalf("%s requires a %d-byte key", cipherName, keyLen)
				}
			}
			var nonce []byte
			if *vector != "" {
				nonce, _ = hex.DecodeString(*vector)
			} else {
				nonce = make([]byte, nonceLen)
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			ciph, _ := zuc.NewCipher(keyRaw, nonce)
			buf := make([]byte, 64*1<<10)
			in := openInput()
			for {
				n, err := in.Read(buf)
				if err != nil && err != io.EOF {
					log.Fatal(err)
				}
				ciph.XORKeyStream(buf[:n], buf[:n])
				os.Stdout.Write(buf[:n])
				if err == io.EOF {
					break
				}
			}
			os.Exit(0)
		}

		// SM4 (GCM / CBC / CTR / OFB / CFB)
		keyHex := *key
		var keyRaw []byte
		var err error
		if *pbkdf {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, sm3.New)
			keyHex = hex.EncodeToString(keyRaw)
		}
		if keyHex == "" {
			keyRaw = make([]byte, 16)
			io.ReadFull(rand.Reader, keyRaw)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 16 {
				log.Fatal("SM4 requires a 16-byte key")
			}
		}
		ciph, err := sm4.NewCipher(keyRaw)
		if err != nil {
			log.Fatal(err)
		}

		modeUpper := strings.ToUpper(*mode)
		switch modeUpper {
		case "GCM":
			aead, err := cipher.NewGCM(ciph)
			if err != nil {
				log.Fatal(err)
			}
			if *crypt == "enc" {
				msg, _ := ioutil.ReadAll(openInput())
				nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
				io.ReadFull(rand.Reader, nonce)
				if *vector != "" {
					nonce, _ = hex.DecodeString(*vector)
				}
				out := aead.Seal(nonce, nonce, msg, []byte(*info))
				os.Stdout.Write(out)
				os.Exit(0)
			}
			msg, _ := ioutil.ReadAll(openInput())
			nonce, ct := msg[:aead.NonceSize()], msg[aead.NonceSize():]
			out, err := aead.Open(nil, nonce, ct, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(out)
			os.Exit(0)

		case "CBC":
			var iv []byte
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
			} else {
				iv = make([]byte, sm4.BlockSize)
				fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
			}
			buf, _ := ioutil.ReadAll(openInput())
			if *crypt == "enc" {
				pad := sm4.BlockSize - len(buf)%sm4.BlockSize
				buf = append(buf, bytes.Repeat([]byte{byte(pad)}, pad)...)
				out := make([]byte, len(buf))
				cipher.NewCBCEncrypter(ciph, iv).CryptBlocks(out, buf)
				os.Stdout.Write(out)
			} else {
				if len(buf)%sm4.BlockSize != 0 {
					log.Fatal("ciphertext length is not a multiple of the block size")
				}
				out := make([]byte, len(buf))
				cipher.NewCBCDecrypter(ciph, iv).CryptBlocks(out, buf)
				if len(out) == 0 {
					os.Exit(0)
				}
				pad := int(out[len(out)-1])
				if pad < 1 || pad > sm4.BlockSize {
					log.Fatal("invalid padding")
				}
				os.Stdout.Write(out[:len(out)-pad])
			}
			os.Exit(0)

		case "CTR", "OFB", "CFB":
			var iv []byte
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
			} else {
				iv = make([]byte, sm4.BlockSize)
				fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
			}
			var stream cipher.Stream
			switch modeUpper {
			case "CTR":
				stream = cipher.NewCTR(ciph, iv)
			case "OFB":
				stream = cipher.NewOFB(ciph, iv)
			case "CFB":
				if *crypt == "enc" {
					stream = cipher.NewCFBEncrypter(ciph, iv)
				} else {
					stream = cipher.NewCFBDecrypter(ciph, iv)
				}
			}
			buf := make([]byte, 64*1<<10)
			in := openInput()
			for {
				n, err := in.Read(buf)
				if err != nil && err != io.EOF {
					log.Fatal(err)
				}
				stream.XORKeyStream(buf[:n], buf[:n])
				os.Stdout.Write(buf[:n])
				if err == io.EOF {
					break
				}
			}
			os.Exit(0)

		default:
			log.Fatalf("Mode %s not supported", *mode)
		}
	}

	// -pbkdf2 / -hkdf (SM3)
	if *pbkdf && *crypt == "" && *mac == "" && *pkey == "" {
		n := *length
		if n == 0 {
			n = 256
		}
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, n/8, sm3.New)
		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}
	if *kdf > 0 {
		hk := hkdf.New(sm3.New, []byte(*key), []byte(*salt), []byte(*info))
		out := make([]byte, *kdf/8)
		if _, err := io.ReadFull(hk, out); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(out))
		os.Exit(0)
	}

	// -tcp (TLCP)
	if *tcpip == "server" || *tcpip == "client" || *tcpip == "ip" {
		handleTLCP()
	}

	// -pkey (SM2 / SM9)
	if *pkey == "keygen" && strings.ToUpper(*alg) == "SM2" && *pwd == "" {
		print("Passphrase: ")
		*pwd = readPassword(true)
	}
	if (*pkey == "certgen" || *pkey == "text" || *pkey == "modulus" || *pkey == "req" || *pkey == "x509" ||
		*pkey == "crl" || *pkey == "sign" || *pkey == "encrypt" || *pkey == "decrypt" || *pkey == "wrapkey" ||
		*pkey == "unwrapkey" || *pkey == "derive" || *pkey == "derivea" || *pkey == "deriveb") &&
		*key != "" && *pwd == "" {
		if f, err := os.Open(*key); err == nil {
			data, _ := ioutil.ReadAll(f)
			f.Close()
			if block, _ := pem.Decode(data); block != nil && IsEncryptedPEMBlock(block) {
				print("Passphrase: ")
				*pwd = readPassword(false)
			}
		}
	}

	// Auto-detect algorithm from the PEM header for -pkey text / modulus.
	if *pkey == "text" || *pkey == "modulus" {
		inputPath := *key
		if inputPath == "" {
			inputPath = *cert
		}
		if inputPath == "" {
			inputPath = *crl
		}
		if inputPath != "" {
			if data, err := ioutil.ReadFile(inputPath); err == nil {
				if block, _ := pem.Decode(data); block != nil {
					switch {
					case strings.Contains(block.Type, "SM9 SIGN"):
						handleSM9SignText(block, data)
					case strings.Contains(block.Type, "SM9 ENC"):
						handleSM9EncryptText(block, data)
					case strings.Contains(block.Type, "EC PRIVATE"),
						strings.Contains(block.Type, "PRIVATE KEY"),
						strings.Contains(block.Type, "SM2 PRIVATE"),
						strings.Contains(block.Type, "PUBLIC KEY"):
						handleSM2Text(block, data)
					case block.Type == "CERTIFICATE":
						handleCertText(block, data)
					case block.Type == "CERTIFICATE REQUEST":
						handleCSRText(block, data)
					case block.Type == "X509 CRL":
						handleCRLText(block, data)
					}
				}
			}
		}
	}

	switch strings.ToUpper(*alg) {
	case "SM2":
		handleSM2()
	case "SM9SIGN":
		handleSM9Sign()
	case "SM9ENCRYPT":
		handleSM9Encrypt()
	default:
		log.Fatalf("algorithm %q not supported (use SM2, SM9SIGN or SM9ENCRYPT)", *alg)
	}
}

// ===========================================================================
// TLCP
// ===========================================================================

func handleTLCP() {
	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}

	if *tcpip != "server" && *tcpip != "client" {
		return
	}

	var cfg tlcp.Config
	cfg.CipherSuites = []uint16{tlcp.ECC_SM4_GCM_SM3, tlcp.ECC_SM4_CBC_SM3}

	// Server always needs a signature keypair.
	// Client only needs one when mutual authentication is desired.
	if *tcpip == "server" || (*cert != "" && *key != "") {
		sigCertData, sigPrivData := loadPlainKeyPair(*cert, *key, *pwd)
		sigcert, err := tlcp.X509KeyPair(sigCertData, sigPrivData)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Certificates = []tlcp.Certificate{sigcert}
	}

	// Optional encryption certificate (server side, dual-cert TLCP).
	if *tcpip == "server" && *cacert != "" && *cakey != "" {
		encCertData, encPrivData := loadPlainKeyPair(*cacert, *cakey, *pwd2)
		enccert, err := tlcp.X509KeyPair(encCertData, encPrivData)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Certificates = append(cfg.Certificates, enccert)
	}

	if *tcpip == "server" {
		// Only enforce client auth when a root CA is provided (-root).
		// Without -root, ClientAuth stays default (NoClientCert) and the
		// server accepts clients without certificates (unilateral auth).
		if *root != "" {
			rootData, err := ioutil.ReadFile(*root)
			if err != nil {
				log.Fatal(err)
			}
			rootBlock, _ := pem.Decode(rootData)
			rootCert, err := smx509.ParseCertificate(rootBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			pool := smx509.NewCertPool()
			pool.AddCert(rootCert)
			cfg.ClientAuth = tlcp.RequireAndVerifyClientCert
			cfg.ClientCAs = pool
		}
		cfg.Rand = rand.Reader
		port := "8081"
		if *iport != "" {
			port = *iport
		}
		ln, err := tlcp.Listen("tcp", ":"+port, &cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "Server(TLCP) up and listening on port "+port)
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()
		tc := conn.(*tlcp.Conn)
		if err := tc.Handshake(); err != nil {
			log.Fatalf("server: handshake failed: %s", err)
		}
		go handleConnectionTLCP(conn)
		for {
			msg, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(3)
			}
			fmt.Print("Client response: " + msg)
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Text to be sent: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(3)
			}
			fmt.Fprintf(conn, text+"\n")
		}
	}

	if *tcpip == "client" {
		// Validate the server chain against -root when provided.
		if *root != "" {
			rootData, err := ioutil.ReadFile(*root)
			if err != nil {
				log.Fatal(err)
			}
			rootBlock, _ := pem.Decode(rootData)
			rootCert, err := smx509.ParseCertificate(rootBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			pool := smx509.NewCertPool()
			pool.AddCert(rootCert)
			cfg.RootCAs = pool
		} else {
			// Without -root, skip server chain verification (unilateral
			// auth; same as edgetk when -root is omitted).
			cfg.InsecureSkipVerify = true
		}
		ipport := "127.0.0.1:8081"
		if *iport != "" {
			ipport = *iport
		}
		conn, err := tlcp.Dial("tcp", ipport, &cfg)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		for _, c := range conn.ConnectionState().PeerCertificates {
			fmt.Printf("Issuer: \n\t%s\n", c.Issuer)
			fmt.Printf("Subject: \n\t%s\n", c.Subject)
			fmt.Printf("Expiry: %s \n", c.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
		}
		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Text to be sent: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(3)
			}
			fmt.Fprintf(conn, text+"\n")
			msg, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(3)
			}
			fmt.Print("Server response: " + msg)
		}
	}
}

// ===========================================================================
// SM2
// ===========================================================================

func handleSM2() {
	switch *pkey {
	case "keygen":
		privateKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		privDER, err := smx509.MarshalSM2PrivateKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}
		f, err := os.Create(*prv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			enc, err := EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			if err != nil {
				log.Fatal(err)
			}
			pem.Encode(f, enc)
		} else {
			pem.Encode(f, block)
		}
		f.Close()

		pubKey := &privateKey.PublicKey
		pubPEM, err := smx509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Fatal(err)
		}
		pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubPEM}
		pf, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		pem.Encode(pf, pubBlock)
		pf.Close()

		absPrivPath, err := filepath.Abs(*prv)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)
		println("SM2 (256-bit)")
		fmt.Println(randomart.FromString(string(pem.EncodeToMemory(pubBlock))))
		os.Exit(0)

	case "text", "modulus":
		inputPath := *key
		if inputPath == "" {
			inputPath = *cert
		}
		if inputPath == "" {
			inputPath = *crl
		}
		if inputPath == "" {
			log.Fatal("no input: use -key, -cert or -crl with -pkey text/modulus")
		}
		keyData, err := ioutil.ReadFile(inputPath)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(keyData)
		if block == nil {
			log.Fatal("no valid PEM block")
		}
		switch block.Type {
		case "CERTIFICATE":
			handleCertText(block, keyData)
		case "CERTIFICATE REQUEST":
			handleCSRText(block, keyData)
		case "X509 CRL":
			handleCRLText(block, keyData)
		default:
			handleSM2Text(block, keyData)
		}

	case "sign":
		priv, err := loadSM2PrivateKey(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		sigBytes, err := priv.Sign(rand.Reader, msg, sm2.DefaultSM2SignerOpts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("SM2(%s)= %x\n", inputName(), sigBytes)
		os.Exit(0)

	case "verify":
		pubKey, err := loadSM2PublicKey(*key)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		sigBytes, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		if sm2.VerifyASN1(pubKey, msg, sigBytes) {
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println("Verified: false")
		os.Exit(1)

	case "encrypt":
		pubKey, err := loadSM2PublicKey(*key)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		ct, err := sm2.EncryptASN1(rand.Reader, pubKey, msg)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(ct)
		os.Exit(0)

	case "decrypt":
		priv, err := loadSM2PrivateKey(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		ct, _ := ioutil.ReadAll(openInput())
		pt, err := sm2.Decrypt(priv, ct)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(pt)
		os.Exit(0)

	case "derive":
		priv, err := loadSM2PrivateKey(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		peerPub, err := loadSM2PublicKey(*pub)
		if err != nil {
			log.Fatal(err)
		}

		// Convert to the ECDH API exposed by gmsm (crypto/ecdh compatible).
		ecdhPriv, err := priv.ECDH()
		if err != nil {
			log.Fatal(err)
		}
		ecdhPub, err := sm2.PublicKeyToECDH(peerPub)
		if err != nil {
			log.Fatal(err)
		}

		shared, err := ecdhPriv.ECDH(ecdhPub)
		if err != nil {
			log.Fatal(err)
		}

		n := *length / 8
		if n == 0 || n > len(shared) {
			n = len(shared)
		}
		fmt.Printf("Shared= %x\n", shared[:n])
		os.Exit(0)

	case "certgen":
		runCertgenSM2()
	case "req":
		runReqSM2()
	case "x509":
		runX509SM2()
	case "crl":
		runCRLSM2()
	case "validate":
		runValidateSM2()
	case "check":
		runCheckSM2()
	case "randomart":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("SM2 (256-bit)")
		fmt.Println(randomart.FromString(string(data)))
		os.Exit(0)
	case "fingerprint":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		h := sm3.Sum(data)
		fmt.Printf("Fingerprint= %x\n", h)
		os.Exit(0)
	}
}

func handleSM2Text(block *pem.Block, keyData []byte) {
	var err error
	var der []byte
	displayPEM := keyData
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			log.Fatal(err)
		}
		displayPEM = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	} else {
		der = block.Bytes
	}

	if strings.Contains(block.Type, "PRIVATE") {
		var priv *sm2.PrivateKey
		if p, err := smx509.ParseECPrivateKey(der); err == nil {
			priv = &sm2.PrivateKey{PrivateKey: *p}
		} else {
			priv, err = smx509.ParseSM2PrivateKey(der)
			if err != nil {
				log.Fatal(err)
			}
		}
		if *pkey == "modulus" {
			fmt.Printf("Public.X=%X\n", priv.PublicKey.X)
			fmt.Printf("Public.Y=%X\n", priv.PublicKey.Y)
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Private-Key: (256-bit)")
		fmt.Println("priv:")
		fmt.Print(formatHexPoints(priv.D.Bytes()))
		pubBytes := elliptic.Marshal(priv.PublicKey.Curve, priv.PublicKey.X, priv.PublicKey.Y)
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pubBytes))
		fmt.Println("Curve: sm2p256v1")
		skid := computeSKID(&priv.PublicKey)
		fmt.Printf("\nKeyID: %x\n", skid)
		os.Exit(0)
	}

	pubKey, err := smx509.ParsePKIXPublicKey(der)
	if err != nil {
		log.Fatal(err)
	}
	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("not an SM2 public key")
	}
	if *pkey == "modulus" {
		fmt.Printf("Public.X=%X\n", ecdsaPub.X)
		fmt.Printf("Public.Y=%X\n", ecdsaPub.Y)
		os.Exit(0)
	}
	fmt.Print(string(displayPEM))
	fmt.Println("Public-Key: (256-bit)")
	fmt.Println("pub.X:")
	fmt.Print(formatHexPoints(ecdsaPub.X.Bytes()))
	fmt.Println("pub.Y:")
	fmt.Print(formatHexPoints(ecdsaPub.Y.Bytes()))
	pubBytes := elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)
	fmt.Println("pub:")
	fmt.Print(formatHexPoints(pubBytes))
	fmt.Println("Curve: sm2p256v1")
	os.Exit(0)
}

// handleCertText parses a PEM CERTIFICATE and dumps it in edgetk/openssl style.
func handleCertText(block *pem.Block, certData []byte) {
	cert, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if *pkey == "modulus" {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("certificate public key is not ECDSA/SM2")
		}
		fmt.Printf("Public.X=%X\n", pub.X)
		fmt.Printf("Public.Y=%X\n", pub.Y)
		os.Exit(0)
	}

	fmt.Printf("Certificate:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Version: %d (0x%x)\n", cert.Version, cert.Version-1)
	fmt.Printf("        Serial Number: %s (0x%x)\n", cert.SerialNumber.String(), cert.SerialNumber)
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("        Issuer: %s\n", reverseNameString(cert.Issuer))
	fmt.Printf("        Validity\n")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.UTC().Format("Jan 2 15:04:05 2006 MST"))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.UTC().Format("Jan 2 15:04:05 2006 MST"))
	fmt.Printf("        Subject: %s\n", reverseNameString(cert.Subject))
	fmt.Printf("        Subject Public Key Info:\n")
	fmt.Printf("            Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		fmt.Printf("                Public-Key: (%d bit)\n", pub.Curve.Params().BitSize)
		printPubKeyXY(pub, "                ")
	}
	fmt.Printf("        X509v3 extensions:\n")
	if cert.KeyUsage != 0 {
		fmt.Printf("            X509v3 Key Usage: critical\n")
		var usages []string
		if cert.KeyUsage&smx509.KeyUsageDigitalSignature != 0 {
			usages = append(usages, "Digital Signature")
		}
		if cert.KeyUsage&smx509.KeyUsageContentCommitment != 0 {
			usages = append(usages, "Content Commitment")
		}
		if cert.KeyUsage&smx509.KeyUsageKeyEncipherment != 0 {
			usages = append(usages, "Key Encipherment")
		}
		if cert.KeyUsage&smx509.KeyUsageDataEncipherment != 0 {
			usages = append(usages, "Data Encipherment")
		}
		if cert.KeyUsage&smx509.KeyUsageKeyAgreement != 0 {
			usages = append(usages, "Key Agreement")
		}
		if cert.KeyUsage&smx509.KeyUsageCertSign != 0 {
			usages = append(usages, "Certificate Sign")
		}
		if cert.KeyUsage&smx509.KeyUsageCRLSign != 0 {
			usages = append(usages, "CRL Sign")
		}
		if cert.KeyUsage&smx509.KeyUsageEncipherOnly != 0 {
			usages = append(usages, "Encipher Only")
		}
		if cert.KeyUsage&smx509.KeyUsageDecipherOnly != 0 {
			usages = append(usages, "Decipher Only")
		}
		fmt.Printf("                %s\n", strings.Join(usages, ", "))
	}
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("            X509v3 Extended Key Usage:\n")
		var ekus []string
		for _, e := range cert.ExtKeyUsage {
			switch e {
			case smx509.ExtKeyUsageServerAuth:
				ekus = append(ekus, "Server Authentication")
			case smx509.ExtKeyUsageClientAuth:
				ekus = append(ekus, "Client Authentication")
			case smx509.ExtKeyUsageCodeSigning:
				ekus = append(ekus, "Code Signing")
			case smx509.ExtKeyUsageEmailProtection:
				ekus = append(ekus, "E-mail Protection")
			case smx509.ExtKeyUsageTimeStamping:
				ekus = append(ekus, "Time Stamping")
			case smx509.ExtKeyUsageOCSPSigning:
				ekus = append(ekus, "OCSP Signing")
			default:
				ekus = append(ekus, fmt.Sprintf("ExtKeyUsage(%d)", e))
			}
		}
		fmt.Printf("                %s\n", strings.Join(ekus, ", "))
	}
	if cert.BasicConstraintsValid {
		fmt.Printf("            X509v3 Basic Constraints: critical\n")
		if cert.IsCA {
			fmt.Printf("                CA:TRUE\n")
		} else {
			fmt.Printf("                CA:FALSE\n")
		}
		if cert.MaxPathLen > 0 {
			fmt.Printf("                MaxPathLen: %d\n", cert.MaxPathLen)
		}
	}
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("            X509v3 Authority Key Identifier:\n")
		fmt.Printf("                keyid:%s\n", strings.ToUpper(hexColonLower(cert.AuthorityKeyId)))
	}
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("            X509v3 Subject Key Identifier:\n")
		fmt.Printf("                %s\n", strings.ToUpper(hexColonLower(cert.SubjectKeyId)))
	}
	if len(cert.EmailAddresses) > 0 || len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Printf("            X509v3 Subject Alternative Name:\n")
		var sans []string
		for _, e := range cert.EmailAddresses {
			sans = append(sans, "email:"+e)
		}
		for _, e := range cert.DNSNames {
			sans = append(sans, "DNS:"+e)
		}
		for _, e := range cert.IPAddresses {
			sans = append(sans, "IP Address:"+e.String())
		}
		fmt.Printf("                %s\n", strings.Join(sans, ", "))
	}
	if len(cert.OCSPServer) > 0 {
		fmt.Printf("            Authority Information Access:\n")
		for _, s := range cert.OCSPServer {
			fmt.Printf("                OCSP - URI:%s\n", s)
		}
	}
	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Printf("            X509v3 CRL Distribution Points:\n")
		for _, s := range cert.CRLDistributionPoints {
			fmt.Printf("                Full Name:\n")
			fmt.Printf("                    URI:%s\n", s)
		}
	}
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Print(indentedHexColonTrail(cert.Signature, "         ", 18))

	valid := time.Now().Before(cert.NotAfter)
	fmt.Println("IsValid:", valid)
	if valid {
		os.Exit(0)
	}
	os.Exit(1)
}

// handleCSRText parses a PEM CERTIFICATE REQUEST and dumps it in edgetk/openssl style.
func handleCSRText(block *pem.Block, csrData []byte) {
	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if *pkey == "modulus" {
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("CSR public key is not ECDSA/SM2")
		}
		fmt.Printf("Public.X=%X\n", pub.X)
		fmt.Printf("Public.Y=%X\n", pub.Y)
		os.Exit(0)
	}

	fmt.Printf("Certificate Request:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Version: 0 (0x0)\n")
	fmt.Printf("        Subject: %s\n", reverseNameString(csr.Subject))
	fmt.Printf("        Subject Public Key Info:\n")
	fmt.Printf("            Public Key Algorithm: %s\n", csr.PublicKeyAlgorithm)
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		fmt.Printf("                Public-Key: (%d bit)\n", pub.Curve.Params().BitSize)
		printPubKeyXY(pub, "                ")
	}
	if len(csr.EmailAddresses) > 0 || len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
		fmt.Printf("        Requested Extensions:\n")
		fmt.Printf("            X509v3 Subject Alternative Name:\n")
		var sans []string
		for _, e := range csr.EmailAddresses {
			sans = append(sans, "email:"+e)
		}
		for _, e := range csr.DNSNames {
			sans = append(sans, "DNS:"+e)
		}
		for _, e := range csr.IPAddresses {
			sans = append(sans, "IP Address:"+e.String())
		}
		fmt.Printf("                %s\n", strings.Join(sans, ", "))
	}
	fmt.Printf("    Signature Algorithm: %s\n", csr.SignatureAlgorithm)
	fmt.Print(indentedHexColonTrail(csr.Signature, "         ", 18))
	os.Exit(0)
}

// handleCRLText parses a PEM X509 CRL and dumps it in edgetk/openssl style.
func handleCRLText(block *pem.Block, crlData []byte) {
	rl, err := smx509.ParseRevocationList(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if *pkey == "modulus" {
		log.Fatal("modulus is not applicable to a CRL")
	}

	// Authority Key Identifier (2.5.29.35).
	var akid []byte
	for _, ext := range rl.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			var id struct {
				Raw           asn1.RawContent
				KeyIdentifier []byte `asn1:"optional,tag:0"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &id); err == nil {
				akid = id.KeyIdentifier
			}
			break
		}
	}

	fmt.Println("CRL:")
	fmt.Println("    Data:")
	fmt.Printf("        Number             : %d (%X)\n", rl.Number, rl.Number)
	fmt.Println("        Last Update        :", rl.ThisUpdate.UTC().Format("Jan 2 15:04:05 2006 MST"))
	fmt.Println("        Next Update        :", rl.NextUpdate.UTC().Format("Jan 2 15:04:05 2006 MST"))
	fmt.Println("        Issuer")
	fmt.Println("            ", reverseNameString(rl.Issuer))
	if len(akid) > 0 {
		fmt.Printf("        Authority Key ID   : keyid:%s\n", strings.ToUpper(hexColonLower(akid)))
	} else {
		fmt.Printf("        Authority Key ID   : \n")
	}
	fmt.Println("    Signature Algorithm:", rl.SignatureAlgorithm)
	fmt.Printf("    Signature:\n")
	fmt.Print(indentedHexColonTrail(rl.Signature, "         ", 18))
	fmt.Println("    Revoked Certificates:")
	if len(rl.RevokedCertificates) == 0 {
		fmt.Println("        (none)")
	}
	for _, rc := range rl.RevokedCertificates {
		fmt.Printf("    - Serial Number: %X\n", rc.SerialNumber)
		fmt.Println("      Revocation Time:", rc.RevocationTime.UTC().Format("Jan 2 15:04:05 2006 MST"))
	}
	os.Exit(0)
}

// parseSM2PrivateKeyDER accepts SEC1 (EC PRIVATE KEY) or PKCS#8 (SM2 PRIVATE KEY).
func parseSM2PrivateKeyDER(der []byte) (*sm2.PrivateKey, error) {
	if ecdsaPriv, err := smx509.ParseECPrivateKey(der); err == nil {
		return &sm2.PrivateKey{PrivateKey: *ecdsaPriv}, nil
	}
	return smx509.ParseSM2PrivateKey(der)
}

func loadSM2PrivateKey(path, password string) (*sm2.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var der []byte
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	return parseSM2PrivateKeyDER(der)
}

func loadSM2PublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	pk, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an SM2 public key (ecdsa-compatible)")
	}
	return pub, nil
}

func runCertgenSM2() {
	privateKey, err := loadSM2PrivateKey(*key, *pwd)
	if err != nil {
		log.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		log.Fatal(err)
	}
	if *subj == "" {
		println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")
		scanner := bufio.NewScanner(os.Stdin)
		print("CommonName: ")
		scanner.Scan()
		name = scanner.Text()
		print("Country: ")
		scanner.Scan()
		country = scanner.Text()
		print("State/Province: ")
		scanner.Scan()
		province = scanner.Text()
		print("Locality: ")
		scanner.Scan()
		locality = scanner.Text()
		print("Organization: ")
		scanner.Scan()
		organization = scanner.Text()
		print("OrganizationUnit: ")
		scanner.Scan()
		organizationunit = scanner.Text()
		print("Email: ")
		scanner.Scan()
		email = scanner.Text()
		print("StreetAddress: ")
		scanner.Scan()
		street = scanner.Text()
		print("PostalCode: ")
		scanner.Scan()
		postalcode = scanner.Text()
		print("SerialNumber: ")
		scanner.Scan()
		number = scanner.Text()
	} else {
		var err error
		name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err =
			parseSubjectString(*subj)
		if err != nil {
			log.Fatal(err)
		}
	}
	validity := *days
	if validity <= 0 {
		fmt.Print("Validity (in Days): ")
		fmt.Scanln(&validity)
	}
	notAfter := time.Now().AddDate(0, 0, validity)

	// SKID/AKID using SM3 (RFC 7093) over the SPKI — same derivation used by
	// the SM2 ecosystem. A self-signed CA uses its own SKID as AKID.
	skid := computeSKID(&privateKey.PublicKey)

	tpl := smx509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: name, SerialNumber: number,
			Country: []string{country}, Province: []string{province},
			Locality: []string{locality}, Organization: []string{organization},
			OrganizationalUnit: []string{organizationunit},
			StreetAddress:      []string{street}, PostalCode: []string{postalcode},
		},
		EmailAddresses:        []string{email},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              smx509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  *isca,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}
	if *isca {
		tpl.KeyUsage |= smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign
	}
	der, err := smx509.CreateCertificate(rand.Reader, &tpl, &tpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(*cert)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Close()
	os.Exit(0)
}

func runReqSM2() {
	priv, err := loadSM2PrivateKey(*key, *pwd)
	if err != nil {
		log.Fatal(err)
	}
	if *subj == "" {
		println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")
		scanner := bufio.NewScanner(os.Stdin)
		print("CommonName: ")
		scanner.Scan()
		name = scanner.Text()
		print("Country: ")
		scanner.Scan()
		country = scanner.Text()
		print("State/Province: ")
		scanner.Scan()
		province = scanner.Text()
		print("Locality: ")
		scanner.Scan()
		locality = scanner.Text()
		print("Organization: ")
		scanner.Scan()
		organization = scanner.Text()
		print("OrganizationUnit: ")
		scanner.Scan()
		organizationunit = scanner.Text()
		print("Email: ")
		scanner.Scan()
		email = scanner.Text()
		print("StreetAddress: ")
		scanner.Scan()
		street = scanner.Text()
		print("PostalCode: ")
		scanner.Scan()
		postalcode = scanner.Text()
		print("SerialNumber: ")
		scanner.Scan()
		number = scanner.Text()
	} else {
		var err error
		name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err =
			parseSubjectString(*subj)
		if err != nil {
			log.Fatal(err)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	subjName := pkix.Name{
		CommonName: name, SerialNumber: number,
		Country: []string{country}, Province: []string{province},
		Locality: []string{locality}, Organization: []string{organization},
		OrganizationalUnit: []string{organizationunit},
		StreetAddress:      []string{street}, PostalCode: []string{postalcode},
	}
	rawSubj, _ := asn1.Marshal(subjName.ToRDNSequence())
	tpl := smx509.CertificateRequest{
		RawSubject:         rawSubj,
		EmailAddresses:     []string{email},
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	der, err := smx509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(*cert)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	f.Close()
	os.Exit(0)
}

func runX509SM2() {
	caData, err := ioutil.ReadFile(*root)
	if err != nil {
		log.Fatal(err)
	}
	caBlock, _ := pem.Decode(caData)
	caCert, err := smx509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if !caCert.IsCA {
		log.Fatal("root certificate is not a valid CA")
	}
	caPriv, err := loadSM2PrivateKey(*key, *pwd)
	if err != nil {
		log.Fatal(err)
	}

	// EDGE Toolkit semantics:
	//   -cert  = CSR (input)
	//   arg 0  = signed certificate (output)
	csrPath := *cert
	if csrPath == "" {
		csrPath = flag.Arg(0)
	}
	if csrPath == "" {
		log.Fatal("no CSR: use -cert <csr.pem> or pass it as the first positional argument")
	}
	csrData, err := ioutil.ReadFile(csrPath)
	if err != nil {
		log.Fatal(err)
	}
	csrBlock, _ := pem.Decode(csrData)
	if csrBlock == nil {
		log.Fatal("no valid PEM block in CSR")
	}
	csr, err := smx509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		log.Fatal("CSR signature verification failed: ", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		log.Fatal(err)
	}
	validity := *days
	if validity <= 0 {
		fmt.Print("Validity (in Days): ")
		fmt.Scanln(&validity)
	}

	// SKID — derive via SM3 from the CSR public key (CSR has no SubjectKeyId).
	var skid []byte
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		skid = computeSKID(pub)
	}

	// AKID — copy the CA's SKID; if missing, derive it via SM3 from the CA key.
	akid := caCert.SubjectKeyId
	if len(akid) == 0 {
		if pub, ok := caCert.PublicKey.(*ecdsa.PublicKey); ok {
			akid = computeSKID(pub)
		}
	}

	tpl := smx509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		Issuer:                caCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validity),
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageContentCommitment | smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment | smx509.KeyUsageKeyAgreement | smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageClientAuth, smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: *isca,
		IsCA:                  *isca,
		SubjectKeyId:          skid,
		AuthorityKeyId:        akid,
	}
	der, err := smx509.CreateCertificate(rand.Reader, &tpl, caCert, csr.PublicKey, caPriv)
	if err != nil {
		log.Fatal(err)
	}

	out := flag.Arg(0)
	if out == "" || out == csrPath {
		out = "cert.crt"
	}
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Close()
	fmt.Fprintln(os.Stderr, "Certificate signed and saved to", out)
	os.Exit(0)
}

func runCRLSM2() {
	caData, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	caBlock, _ := pem.Decode(caData)
	caCert, err := smx509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	caPriv, err := loadSM2PrivateKey(*key, *pwd)
	if err != nil {
		log.Fatal(err)
	}

	// Input: serials.txt (arg 0) or stdin.
	var serialReader io.Reader
	if flag.Arg(0) != "" {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		serialReader = f
	} else {
		serialReader = os.Stdin
	}

	var revoked []pkix.RevokedCertificate
	seen := map[string]bool{}
	sc := bufio.NewScanner(serialReader)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "-----") {
			continue
		}
		// gosttk accepts both decimal and hex; try decimal first.
		serial, ok := new(big.Int).SetString(s, 10)
		if !ok {
			serial, ok = new(big.Int).SetString(s, 16)
			if !ok {
				log.Fatalf("invalid serial: %s", s)
			}
		}
		if seen[serial.String()] {
			continue
		}
		seen[serial.String()] = true
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}

	// -crl is optional: when supplied, it is the *old* CRL whose
	// RevokedCertificates (and RevocationTime) are carried over into the new
	// one. When omitted, the new CRL contains only the serials from the
	// input (gosttk semantics).
	if *crl != "" {
		oldData, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal(err)
		}
		oldBlock, _ := pem.Decode(oldData)
		if oldBlock == nil {
			log.Fatal("no valid PEM block in old CRL")
		}
		oldRL, err := smx509.ParseRevocationList(oldBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		for _, rc := range oldRL.RevokedCertificates {
			key := rc.SerialNumber.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			revoked = append(revoked, rc) // keep original RevocationTime
		}
	}

	rl := &smx509.RevocationList{
		RevokedCertificates: revoked,
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := smx509.CreateRevocationList(rand.Reader, rl, caCert, caPriv)
	if err != nil {
		log.Fatal(err)
	}

	// Output: arg 1 if provided, otherwise stdout (gosttk semantics).
	var output io.Writer = os.Stdout
	if flag.Arg(1) != "" {
		f, err := os.Create(flag.Arg(1))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		output = f
	}
	pem.Encode(output, &pem.Block{Type: "X509 CRL", Bytes: der})
	os.Exit(0)
}

func runValidateSM2() {
	crlData, err := ioutil.ReadFile(*crl)
	if err != nil {
		log.Fatal("Failed to read CRL file:", err)
	}
	crlBlock, _ := pem.Decode(crlData)
	crl, err := smx509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to parse CRL:", err)
	}
	certData, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatal("Failed to read certificate file:", err)
	}
	certBlock, _ := pem.Decode(certData)
	cert, err := smx509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to parse certificate:", err)
	}
	for _, rc := range crl.RevokedCertificates {
		if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			fmt.Println("The certificate is revoked")
			fmt.Println("Revocation Time:", rc.RevocationTime)
			os.Exit(1)
		}
	}
	fmt.Println("The certificate is not revoked")
	os.Exit(0)
}

func runCheckSM2() {
	certData, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	certBlock, _ := pem.Decode(certData)
	cert, err := smx509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyData)
	pubKey, err := smx509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("not an SM2 public key")
	}
	if sm2.VerifyASN1WithSM2(ecdsaPub, nil, cert.RawTBSCertificate, cert.Signature) {
		fmt.Println("Verified: true")
		os.Exit(0)
	}
	fmt.Println("Verified: false")
	os.Exit(1)
}

// ===========================================================================
// SM9 — Sign
// ===========================================================================

func handleSM9Sign() {
	switch *pkey {
	case "setup":
		if *pwd == "" {
			print("MasterKey Passphrase: ")
			*pwd = readPassword(true)
		} else if *pwd == "nil" {
			*pwd = ""
		}
		masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		der, err := smx509.MarshalPKCS8PrivateKey(masterKey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "SM9 SIGN MASTER KEY", Bytes: der}
		f, err := os.Create(*master)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			enc, err := EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			if err != nil {
				log.Fatal(err)
			}
			pem.Encode(f, enc)
		} else {
			pem.Encode(f, block)
		}
		f.Close()

		pubBytes, err := masterKey.Public().(*sm9.SignMasterPublicKey).MarshalASN1()
		if err != nil {
			log.Fatal(err)
		}
		pf, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		pem.Encode(pf, &pem.Block{Type: "SM9 SIGN PUBLIC KEY", Bytes: pubBytes})
		pf.Close()

		absPrivPath, _ := filepath.Abs(*master)
		absPubPath, _ := filepath.Abs(*pub)
		println("Master key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)
		println("SM9 Sign Master Public Key (256-bit)")
		fmt.Println(randomart.FromString(string(pem.EncodeToMemory(&pem.Block{Type: "SM9 SIGN PUBLIC KEY", Bytes: pubBytes}))))
		os.Exit(0)

	case "keygen":
		if *pwd == "" {
			if data, err := ioutil.ReadFile(*master); err == nil {
				if block, _ := pem.Decode(data); block != nil && IsEncryptedPEMBlock(block) {
					print("MasterKey Passphrase: ")
					*pwd = readPassword(false)
				}
			}
		}
		masterPriv, err := loadSM9SignMaster(*master, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		userKey, err := masterPriv.GenerateUserKey([]byte(*id), byte(*hierarchy))
		if err != nil {
			log.Fatal(err)
		}
		der, err := smx509.MarshalPKCS8PrivateKey(userKey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "SM9 SIGN PRIVATE KEY", Bytes: der}
		f, err := os.Create(*prv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			enc, err := EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSM4)
			if err != nil {
				log.Fatal(err)
			}
			pem.Encode(f, enc)
		} else {
			pem.Encode(f, block)
		}
		f.Close()
		absPrivPath, _ := filepath.Abs(*prv)
		println("User key saved to:", absPrivPath)
		os.Exit(0)

	case "text", "modulus":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatal("no valid PEM block")
		}
		handleSM9SignText(block, data)

	case "sign":
		priv, err := loadSM9SignUser(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		sigBytes, err := sm9.SignASN1(rand.Reader, priv, msg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("SM9(%s)= %x\n", inputName(), sigBytes)
		os.Exit(0)

	case "verify":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		pubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		sigBytes, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		if sm9.VerifyASN1(pubKey, []byte(*id), byte(*hierarchy), msg, sigBytes) {
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println("Verified: false")
		os.Exit(1)
	}
}

func handleSM9SignText(block *pem.Block, keyData []byte) {
	var err error
	var der []byte
	displayPEM := keyData
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			log.Fatal(err)
		}
		displayPEM = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	} else {
		der = block.Bytes
	}

	switch block.Type {
	case "SM9 SIGN PUBLIC KEY":
		pub, err := sm9.UnmarshalSignMasterPublicKeyASN1(der)
		if err != nil {
			log.Fatal(err)
		}
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pub.Bytes())
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Sign Public-Key: (256-bit)")
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pub.Bytes()))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)

	case "SM9 SIGN MASTER KEY":
		parsed, err := smx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Fatal(err)
		}
		master := parsed.(*sm9.SignMasterPrivateKey)
		pubBytes := master.Public().(*sm9.SignMasterPublicKey).Bytes()
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pubBytes)
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Sign Master-Key: (256-bit)")
		fmt.Println("master:")
		fmt.Print(formatHexPoints(master.Bytes()))
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pubBytes))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)

	case "SM9 SIGN PRIVATE KEY":
		parsed, err := smx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Fatal(err)
		}
		priv := parsed.(*sm9.SignPrivateKey)
		pubBytes := priv.MasterPublic().Bytes()
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pubBytes)
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Sign Private-Key: (256-bit)")
		fmt.Println("priv:")
		fmt.Print(formatHexPoints(priv.Bytes()))
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pubBytes))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)
	}
	log.Fatal("unknown SM9 SIGN PEM type: " + block.Type)
}

func loadSM9SignMaster(path, password string) (*sm9.SignMasterPrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var der []byte
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	k, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	m, ok := k.(*sm9.SignMasterPrivateKey)
	if !ok {
		return nil, errors.New("not an SM9 Sign Master key")
	}
	return m, nil
}

func loadSM9SignUser(path, password string) (*sm9.SignPrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var der []byte
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	k, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	m, ok := k.(*sm9.SignPrivateKey)
	if !ok {
		return nil, errors.New("not an SM9 Sign user key")
	}
	return m, nil
}

// ===========================================================================
// SM9 — Encrypt
// ===========================================================================

func handleSM9Encrypt() {
	switch *pkey {
	case "setup":
		if *pwd == "" {
			print("MasterKey Passphrase: ")
			*pwd = readPassword(true)
		} else if *pwd == "nil" {
			*pwd = ""
		}
		masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		der, err := smx509.MarshalPKCS8PrivateKey(masterKey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "SM9 ENC MASTER KEY", Bytes: der}
		f, err := os.Create(*master)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			enc, err := EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherSM4)
			if err != nil {
				log.Fatal(err)
			}
			pem.Encode(f, enc)
		} else {
			pem.Encode(f, block)
		}
		f.Close()

		pubBytes, err := masterKey.Public().(*sm9.EncryptMasterPublicKey).MarshalASN1()
		if err != nil {
			log.Fatal(err)
		}
		pf, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		pem.Encode(pf, &pem.Block{Type: "SM9 ENC PUBLIC KEY", Bytes: pubBytes})
		pf.Close()

		absPrivPath, _ := filepath.Abs(*master)
		absPubPath, _ := filepath.Abs(*pub)
		println("Master key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)
		println("SM9 Encrypt Master Public Key (256-bit)")
		fmt.Println(randomart.FromString(string(pem.EncodeToMemory(&pem.Block{Type: "SM9 ENC PUBLIC KEY", Bytes: pubBytes}))))
		os.Exit(0)

	case "keygen":
		if *pwd == "" {
			if data, err := ioutil.ReadFile(*master); err == nil {
				if block, _ := pem.Decode(data); block != nil && IsEncryptedPEMBlock(block) {
					print("MasterKey Passphrase: ")
					*pwd = readPassword(false)
				}
			}
		}
		masterPriv, err := loadSM9EncMaster(*master, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		userKey, err := masterPriv.GenerateUserKey([]byte(*id), byte(*hierarchy))
		if err != nil {
			log.Fatal(err)
		}
		der, err := smx509.MarshalPKCS8PrivateKey(userKey)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "SM9 ENC PRIVATE KEY", Bytes: der}
		f, err := os.Create(*prv)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd2 != "" {
			enc, err := EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd2), PEMCipherSM4)
			if err != nil {
				log.Fatal(err)
			}
			pem.Encode(f, enc)
		} else {
			pem.Encode(f, block)
		}
		f.Close()
		absPrivPath, _ := filepath.Abs(*prv)
		println("User key saved to:", absPrivPath)
		os.Exit(0)

	case "text", "modulus":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatal("no valid PEM block")
		}
		handleSM9EncryptText(block, data)

	case "encrypt":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		msg, _ := ioutil.ReadAll(openInput())
		ct, err := sm9.EncryptASN1(rand.Reader, pubKey, []byte(*id), byte(*hierarchy), msg, sm9.DefaultEncrypterOpts)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(ct)
		os.Exit(0)

	case "decrypt":
		priv, err := loadSM9EncUser(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		ct, _ := ioutil.ReadAll(openInput())
		pt, err := priv.DecryptASN1([]byte(*id), ct)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(pt)
		os.Exit(0)

	case "wrapkey":
		data, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(data)
		pubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		keyLen := *length / 8
		if keyLen == 0 {
			keyLen = 32
		}
		kp, err := pubKey.WrapKeyASN1(rand.Reader, []byte(*id), byte(*hierarchy), keyLen)
		if err != nil {
			log.Fatal(err)
		}
		k, ct, err := sm9.UnmarshalSM9KeyPackage(kp)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Cipher= %x\n", ct)
		fmt.Printf("Shared= %x\n", k)
		os.Exit(0)

	case "unwrapkey":
		priv, err := loadSM9EncUser(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		cipherHex := strings.ReplaceAll(strings.ReplaceAll(*cph, " ", ""), "\n", "")
		ct, err := hex.DecodeString(cipherHex)
		if err != nil {
			log.Fatal(err)
		}
		keyLen := *length / 8
		if keyLen == 0 {
			keyLen = 32
		}
		k, err := sm9.UnwrapKey(priv, []byte(*id), ct, keyLen)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Shared= %x\n", k)
		os.Exit(0)

	case "derivea":
		priv, err := loadSM9EncUser(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		keyLen := *length / 8
		if keyLen == 0 {
			keyLen = 16
		}
		ex := priv.NewKeyExchange([]byte(*id), []byte(*id2), keyLen, true)
		defer ex.Destroy()
		rA, err := ex.InitKeyExchange(rand.Reader, byte(*hierarchy))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("rA=", hex.EncodeToString(rA))
		var rB, signB string
		fmt.Print("Enter rB: ")
		fmt.Scanln(&rB)
		fmt.Print("Enter signB: ")
		fmt.Scanln(&signB)
		rBBytes, _ := hex.DecodeString(rB)
		signBBytes, _ := hex.DecodeString(signB)
		sharedKey, _, err := ex.ConfirmResponder(rBBytes, signBBytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Shared=", hex.EncodeToString(sharedKey))
		os.Exit(0)

	case "deriveb":
		priv, err := loadSM9EncUser(*key, *pwd)
		if err != nil {
			log.Fatal(err)
		}
		keyLen := *length / 8
		if keyLen == 0 {
			keyLen = 16
		}
		var rA string
		fmt.Print("Enter rA: ")
		fmt.Scanln(&rA)
		rABytes, _ := hex.DecodeString(rA)
		ex := priv.NewKeyExchange([]byte(*id), []byte(*id2), keyLen, true)
		defer ex.Destroy()
		rB, sigB, err := ex.RespondKeyExchange(rand.Reader, byte(*hierarchy), rABytes)
		if err != nil {
			log.Fatal(err)
		}
		sharedKey, err := ex.ConfirmInitiator(nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("rB=", hex.EncodeToString(rB))
		fmt.Println("signB=", hex.EncodeToString(sigB))
		fmt.Println("Shared=", hex.EncodeToString(sharedKey))
		os.Exit(0)
	}
}

func handleSM9EncryptText(block *pem.Block, keyData []byte) {
	var err error
	var der []byte
	displayPEM := keyData
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(*pwd))
		if err != nil {
			log.Fatal(err)
		}
		displayPEM = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	} else {
		der = block.Bytes
	}

	switch block.Type {
	case "SM9 ENC PUBLIC KEY":
		pub, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(der)
		if err != nil {
			log.Fatal(err)
		}
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pub.Bytes())
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Encrypt Public-Key: (256-bit)")
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pub.Bytes()))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)

	case "SM9 ENC MASTER KEY":
		parsed, err := smx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Fatal(err)
		}
		master := parsed.(*sm9.EncryptMasterPrivateKey)
		pubBytes := master.Public().(*sm9.EncryptMasterPublicKey).Bytes()
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pubBytes)
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Encrypt Master-Key: (256-bit)")
		fmt.Println("master:")
		fmt.Print(formatHexPoints(master.Bytes()))
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pubBytes))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)

	case "SM9 ENC PRIVATE KEY":
		parsed, err := smx509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Fatal(err)
		}
		priv := parsed.(*sm9.EncryptPrivateKey)
		pubBytes := priv.MasterPublic().Bytes()
		if *pkey == "modulus" {
			fmt.Printf("Public=%X\n", pubBytes)
			os.Exit(0)
		}
		fmt.Print(string(displayPEM))
		fmt.Println("Encrypt Private-Key: (256-bit)")
		fmt.Println("priv:")
		fmt.Print(formatHexPoints(priv.Bytes()))
		fmt.Println("pub:")
		fmt.Print(formatHexPoints(pubBytes))
		fmt.Println("Curve: sm9p256v1")
		os.Exit(0)
	}
	log.Fatal("unknown SM9 ENCRYPT PEM type: " + block.Type)
}

func loadSM9EncMaster(path, password string) (*sm9.EncryptMasterPrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var der []byte
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	k, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	m, ok := k.(*sm9.EncryptMasterPrivateKey)
	if !ok {
		return nil, errors.New("not an SM9 Encrypt Master key")
	}
	return m, nil
}

func loadSM9EncUser(path, password string) (*sm9.EncryptPrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var der []byte
	if IsEncryptedPEMBlock(block) {
		der, err = DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	k, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	m, ok := k.(*sm9.EncryptPrivateKey)
	if !ok {
		return nil, errors.New("not an SM9 Encrypt user key")
	}
	return m, nil
}

// ===========================================================================
// Banner
// ===========================================================================

func printBanner() {
	bin := os.Args[0]
	fmt.Println(`GMSMTk v` + Version + `  ` + VersionDate + `
ShangMi (SM) and ZUC toolkit: SM2, SM3, SM4, ZUC-128/256, SM9 and TLCP.

USAGE
  ` + bin + ` [flags] [input-file]
  cat file | ` + bin + ` [flags]

HASHES
  -digest FILE|-   SM3 hash a file, wildcard or STDIN
  -recursive       walk directories recursively
  -check FILE|-    verify a hashsum list

MACs
  -mac zuc128|zuc256|eia128|eia256|hmac|cmac
  -key HEX              secret key (hex)
  -signature HEX        expected MAC

SYMMETRIC CIPHERS
  -crypt enc|dec        encrypt/decrypt
  -cipher sm4|zuc128|zuc256
  -mode GCM|CBC|CTR|OFB|CFB
  -key HEX              key (hex)
  -iv HEX               initialization vector
  -info STRING          additional authenticated data (GCM)

KEYS AND CERTIFICATES
  -algorithm SM2|SM9SIGN|SM9ENCRYPT
  -pkey keygen|certgen|req|x509|crl|check|validate|
        text|modulus|randomart|fingerprint|
        sign|verify|encrypt|decrypt|
        setup|wrapkey|unwrapkey|derivea|deriveb
  -key  -pub  -pass  -master  -id  -peerid  -hid
  -subj  -days  -isca  -root  -cert  -crl

TLCP
  -tcp server|client|ip
  -ipport ADDR
  -cacert  -cakey  -root

EXAMPLES  (SM2 is the default)
  ` + bin + ` -digest file.txt
  ` + bin + ` -digest '*.go' -recursive
  ` + bin + ` -pkey keygen -prv SM2.pem -pub SM2.pub
  ` + bin + ` -pkey certgen -key SM2.pem -cert CA.crt -isca -days 3650
  ` + bin + ` -pkey sign   -key SM2.pem file.txt
  ` + bin + ` -pkey verify -key SM2.pub -signature HEX file.txt
  ` + bin + ` -pkey text   -cert Certificate.pem
  ` + bin + ` -pkey text   -crl CRL.pem
  ` + bin + ` -pkey x509   -key CA.key -root CA.crt -cert CSR.pem
  ` + bin + ` -pkey crl    -key CA.key -cert CA.crt serials.txt
  ` + bin + ` -cipher sm4    -crypt enc -key 00112233... < in > out
  ` + bin + ` -cipher zuc256 -crypt enc -key ... < in > out
  ` + bin + ` -mac zuc256 -key ... < file
  ` + bin + ` -tcp server -cert S.crt -key S.key -cacert CA.crt -cakey CA.key

EXAMPLES  (SM9)
  ` + bin + ` -algorithm SM9SIGN -pkey setup -master M.pem -pass 123 -pub M.pub
  ` + bin + ` -algorithm SM9SIGN -pkey keygen -master M.pem -id alice -prv A.pem
  ` + bin + ` -algorithm SM9SIGN -pkey sign   -key alice.pem file.txt
  ` + bin + ` -algorithm SM9SIGN -pkey verify -key M.pub -id alice
  ` + bin + ` -algorithm SM9ENCRYPT -pkey setup -master M.pem -pass 123
  ` + bin + ` -algorithm SM9ENCRYPT -pkey keygen -master M.pem -id bob
  ` + bin + ` -algorithm SM9ENCRYPT -pkey encrypt -key M.pub -id bob -hid 1
  ` + bin + ` -algorithm SM9ENCRYPT -pkey decrypt -key bob.pem -id bob
  ` + bin + ` -algorithm SM9ENCRYPT -pkey wrapkey -key M.pub -id bob -hid 1
  ` + bin + ` -algorithm SM9ENCRYPT -pkey unwrapkey -key bob.pem -id bob

OPTIONS
  -version              print version and exit
  -h, --help            print all flags`)
}

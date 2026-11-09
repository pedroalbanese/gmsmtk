# :cn: GMSM Toolkit ☭

[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gmsmtk/blob/master/LICENSE.md)
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gmsmtk?status.png)](http://godoc.org/github.com/pedroalbanese/gmsmtk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/gmsmtk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/gmsmtk/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/gmsmtk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gmsmtk)](https://github.com/pedroalbanese/gmsmtk/releases)

Multi-purpose cross-platform cryptography tool for asymmetric/symmetric encryption, digital signature, cipher-based message authentication code (CMAC), hash digest, hash-based message authentication code (HMAC), PBKDF2/HKDF functions, PEM key/certificate management, X.509 CSR/CRL and **TLCP** (SM2 + SM4-GCM/CBC-SM3).

#### Chinese National Standard Algorithms:
* GM/T 0003-2012 — SM2 public key algorithm 256-bit.
* GM/T 0004-2012 — SM3 message digest algorithm, 256-bit hash value.
* GM/T 0002-2012 — SM4 128-bit block cipher with 128-bit key.
* GM/T 0001-2012 — ZUC (Zu Chongzhi) stream cipher 128/256-bit key.
* GM/T 0044-2016 — SM9 identity-based cryptographic algorithms.
* GB/T 38636-2020 — TLCP Transport Layer Cryptography Protocol.

#### Modes of operation:
* GCM: Galois/Counter Mode (AEAD, default)
* CBC: Cipher Block Chaining
* CTR: Counter Mode
* OFB: Output Feedback Mode
* CFB: Cipher Feedback Mode

#### Cryptographic Functions:
* Asymmetric Encryption (SM2, SM9)
* Symmetric Encryption + AEAD mode (SM4)
* Stream Encryption (ZUC-128/256)
* Digital Signature (SM2-ECDSA, SM9)
* Shared Key Agreement (SM2-ECDH, SM9)
* Recursive Hash Digest + Check (SM3)
* CMAC (Cipher-based message authentication code)
* HMAC (Hash-based message authentication code)
* HKDF (HMAC-based key derivation function)
* PBKDF2 (Password-based key derivation function 2)
* TLCP (Transport Layer Cryptography Protocol)
* PEM key/certificate management (encrypted private keys via SM4-CBC)

#### Non-Cryptographic Functions:
* Bin to Hex / Hex to Bin string conversion
* Random Art (Public key fingerprint)

---

### Usage 用法:

```text
 -algorithm string
       Algorithm: SM2, SM9SIGN, SM9ENCRYPT. (default "SM2")
 -bits int
       Key length (bits).
 -cacert string
       CA certificate path. (for TLCP Protocol)
 -cakey string
       CA private key. (for TLCP Protocol)
 -cert string
       Certificate path.
 -check string
       Check hashsum file. ('-' for STDIN)
 -cipher string
       Symmetric cipher: sm4, zuc128, zuc256. (default "sm4")
 -crypt string
       Bulk encryption with SM4/ZUC. [enc|dec]
 -days int
       Certificate validity (days).
 -digest string
       File/Wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode/Decode/Dump hex. [enc|dec|dump]
 -hid uint
       Hierarchy Identifier (SM9). (default 0x01)
 -hkdf int
       HKDF output bit length (0 = off).
 -id string
       User Identifier (SM9).
 -info string
       Associated data / additional info.
 -ipport string
       Local Port/remote side IP:Port.
 -isca
       The requested CSR is for a Certificate Authority (CA).
 -iter int
       Iterations (PBKDF2). (default 1)
 -iv string
       Initialization Vector.
 -key string
       Asymmetric/symmetric key or HMAC key.
 -mac string
       MAC: zuc128|zuc256|eia128|eia256|hmac|cmac.
 -master string
       Master key path (SM9 setup). (default "Master.pem")
 -md string
       Message digest: sm3. (default "sm3")
 -mode string
       Mode: GCM, CBC, CTR, OFB, CFB. (default "GCM")
 -pass string
       Password (PEM encryption).
 -passout string
       User Password (SM9 user key PEM encryption).
 -pbkdf2
       Password-based key derivation function 2.
 -peerid string
       Remote User Identifier (SM9 key exchange).
 -pkey string
       Subcommands: keygen|certgen|req|x509|crl|check|validate|
                    text|modulus|randomart|fingerprint|
                    sign|verify|encrypt|decrypt|
                    setup|wrapkey|unwrapkey|derivea|deriveb
 -prv string
       Private key output path. (default "Private.pem")
 -pub string
       Public key output path. (default "Public.pem")
 -rand int
       Generate random key (bits: 64|128|256|512).
 -recursive
       Process directories recursively.
 -root string
       Root CA Certificate path.
 -salt string
       Salt (PBKDF2 / HKDF).
 -signature string
       Input signature (verification).
 -subj string
       Subject: "/CN=/OU=/O=/ST=/L=/C=/emailAddress=".
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [server|client|ip]
 -version
       Print version info.
```

---

### Examples:

#### SM2 — keypair generation (PEM):
```bash
./gmsmtk -algorithm SM2 -pkey keygen -prv Private.pem -pub Public.pem [-bits 256] [-pass "pass"]
```

#### SM2 — shared secret derivation (ECDH):
```bash
./gmsmtk -algorithm SM2 -pkey derive -key Private.pem -pub RemotePublic.pem [-bits 64|128|256]
```

#### SM2 — digital signature (ECDSA):
```bash
./gmsmtk -algorithm SM2 -pkey sign -key Private.pem < file.ext > sign.txt
sign=$(cat sign.txt | awk '{print $2}')
./gmsmtk -algorithm SM2 -pkey verify -key Public.pem -signature "$sign" < file.ext
echo $?
```

#### SM2 — asymmetric encryption / decryption:
```bash
./gmsmtk -algorithm SM2 -pkey encrypt -key Public.pem < plaintext.ext > ciphertext.ext
./gmsmtk -algorithm SM2 -pkey decrypt -key Private.pem < ciphertext.ext > plaintext.ext
```

#### SM2 — self-signed certificate:
```bash
./gmsmtk -algorithm SM2 -pkey certgen -key Private.pem -cert Certificate.pem \
  -subj "/CN=example.com/O=MyOrg/OU=TI/C=BR/ST=SP/L=SaoPaulo" -days 365 [-isca]
```

#### SM2 — certificate signing request (CSR):
```bash
./gmsmtk -algorithm SM2 -pkey req -key Private.pem -cert Request.csr \
  -subj "/CN=example.com/O=MyOrg/OU=TI/C=BR/ST=SP/L=SaoPaulo/emailAddress=admin@example.com"
```

#### SM2 — sign CSR with a CA (X.509):
```bash
./gmsmtk -algorithm SM2 -pkey x509 -root CA.crt -key CA.key \
  -cert Request.csr [-days 365] Signed.crt
```

#### SM2 — generate CRL:
```bash
./gmsmtk -algorithm SM2 -pkey crl -key CA.key -cert CA.crt serials.txt CRL.pem
```

#### SM2 — validate certificate against CRL:
```bash
./gmsmtk -algorithm SM2 -pkey validate -cert Signed.crt -crl CRL.pem
```

#### SM2 — verify certificate signature:
```bash
./gmsmtk -algorithm SM2 -pkey check -cert Signed.crt -key CA.pub
```

#### SM2/SM9 — parse keys (text or short modulus):
```bash
./gmsmtk -pkey text    -key Private.pem [-pass "pass"]
./gmsmtk -pkey text    -key Public.pem
./gmsmtk -pkey modulus -key Private.pem [-pass "pass"]
./gmsmtk -pkey modulus -key Public.pem
```

#### SM2/SM9 — RandomArt / fingerprint of a public key:
```bash
./gmsmtk -pkey randomart   -key Public.pem
./gmsmtk -pkey fingerprint -key Public.pem
```

#### SM9 — KGC setup (sign variant):
```bash
./gmsmtk -algorithm SM9SIGN -pkey setup -master MasterSign.pem -pub MasterSignPub.pem [-pass "pass"]
```

#### SM9 — KGC setup (encrypt variant):
```bash
./gmsmtk -algorithm SM9ENCRYPT -pkey setup -master MasterEnc.pem -pub MasterEncPub.pem [-pass "pass"]
```

#### SM9 — user key extraction:
```bash
./gmsmtk -algorithm SM9SIGN    -pkey keygen -master MasterSign.pem   -id alice -prv FulanoSign.pem   [-pass "pass" -passout "pass"]
./gmsmtk -algorithm SM9ENCRYPT -pkey keygen -master MasterEnc.pem    -id alice -prv FulanoEnc.pem    [-pass "pass" -passout "pass"]
```

#### SM9 — sign / verify:
```bash
./gmsmtk -algorithm SM9SIGN -pkey sign   -key FulanoSign.pem < file.ext > sign.txt
./gmsmtk -algorithm SM9SIGN -pkey verify -key MasterSignPub.pem -id alice -signature "$sign" < file.ext
```

#### SM9 — encrypt / decrypt:
```bash
./gmsmtk -algorithm SM9ENCRYPT -pkey encrypt -key MasterEncPub.pem -id alice < plaintext.ext > ciphertext.ext
./gmsmtk -algorithm SM9ENCRYPT -pkey decrypt -key FulanoEnc.pem    -id alice < ciphertext.ext > plaintext.ext
```

#### SM9 — wrap / unwrap key:
```bash
./gmsmtk -algorithm SM9ENCRYPT -pkey wrapkey   -key MasterEncPub.pem -id fulano -hid 1 -bits 256
./gmsmtk -algorithm SM9ENCRYPT -pkey unwrapkey -key FulanoEnc.pem    -id fulano -bits 256 -cipher "$cipher"
```

#### SM9 — key exchange (A and B sides):
```bash
./gmsmtk -algorithm SM9ENCRYPT -pkey derivea -key FulanoEnc.pem  -id fulano  -peerid sicrano -bits 128
./gmsmtk -algorithm SM9ENCRYPT -pkey deriveb -key SicranoEnc.pem -id sicrano -peerid fulano  -bits 128
```

#### SM9 — parse keys (text or short modulus):
```bash
./gmsmtk -pkey text    -key MasterSign.pem
./gmsmtk -pkey text    -key MasterSignPub.pem
./gmsmtk -pkey text    -key FulanoSign.pem
./gmsmtk -pkey modulus -key MasterEncPub.pem
```

#### SM4 — symmetric encryption / decryption:
```bash
./gmsmtk -cipher sm4 -crypt enc -key 0123456789abcdeffedcba9876543210 < plaintext.ext > ciphertext.ext
./gmsmtk -cipher sm4 -crypt dec -key 0123456789abcdeffedcba9876543210 < ciphertext.ext > plaintext.ext
```

#### SM4 — non-AEAD modes (CBC / CTR / OFB / CFB):
```bash
./gmsmtk -cipher sm4 -crypt enc -mode CBC -key $key -iv $iv < plaintext.ext > ciphertext.ext
./gmsmtk -cipher sm4 -crypt enc -mode CTR -key $key -iv $iv < plaintext.ext > ciphertext.ext
./gmsmtk -cipher sm4 -crypt enc -mode OFB -key $key -iv $iv < plaintext.ext > ciphertext.ext
./gmsmtk -cipher sm4 -crypt enc -mode CFB -key $key -iv $iv < plaintext.ext > ciphertext.ext
```

#### SM4 — GCM with additional authenticated data:
```bash
./gmsmtk -cipher sm4 -crypt enc -mode GCM -key $key -info "AAD" < plaintext.ext > ciphertext.ext
```

#### ZUC-128 — stream encryption / decryption:
```bash
./gmsmtk -cipher zuc128 -crypt enc -key $128bitkey -iv $128bitiv < plaintext.ext > ciphertext.ext
./gmsmtk -cipher zuc128 -crypt dec -key $128bitkey -iv $128bitiv < ciphertext.ext > plaintext.ext
```

#### ZUC-256 — stream encryption / decryption:
```bash
./gmsmtk -cipher zuc256 -crypt enc -key $256bitkey -iv $184bitiv < plaintext.ext > ciphertext.ext
./gmsmtk -cipher zuc256 -crypt dec -key $256bitkey -iv $184bitiv < ciphertext.ext > plaintext.ext
```

#### CMAC-SM4 (cipher-based message authentication code):
```bash
./gmsmtk -mac cmac -cipher sm4 -key $128bitkey < file.ext
./gmsmtk -mac cmac -cipher sm4 -key $128bitkey -signature $128bitmac < file.ext
```

#### EIA-128 / ZUC-128 MAC:
```bash
./gmsmtk -mac eia128 -key $128bitkey -iv $128bitiv < file.ext
./gmsmtk -mac eia128 -key $128bitkey -iv $128bitiv -signature $32bitmac < file.ext
```

#### EIA-256 / ZUC-256 MAC:
```bash
./gmsmtk -mac eia256 -key $256bitkey -iv $184bitiv -bits 32 < file.ext
./gmsmtk -mac eia256 -key $256bitkey -iv $184bitiv -bits 32 -signature $mac < file.ext
```

#### HMAC-SM3 (hash-based message authentication code):
```bash
./gmsmtk -mac hmac -key $128bitkey < file.ext
./gmsmtk -mac hmac -key $128bitkey -signature $256bitmac < file.ext
```

#### SM3 — hashsum (list or single):
```bash
./gmsmtk -digest "*.*" [-recursive]
./gmsmtk -digest - < file.ext
```

#### SM3 — check hashsum file:
```bash
./gmsmtk -check hashsum.txt
```

#### PBKDF2 (password-based key derivation function 2):
```bash
./gmsmtk -pbkdf2 -key "pass" -iter 10000 -salt "salt" -bits 256
```

#### PBKDF2 combined with CRYPT / HMAC:
```bash
./gmsmtk -cipher sm4 -crypt enc -pbkdf2 -key "pass" -iter 10000 -salt "salt" < plaintext.ext > ciphertext.ext
./gmsmtk -mac hmac -pbkdf2 -key "pass" -iter 10000 -salt "salt" < file.ext
```

#### HKDF (HMAC-based key derivation function):
```bash
./gmsmtk -hkdf 256 -key "IKM" -salt "salt" -info "AAD"
```

#### TLCP — server / client (mutual authentication):
```bash
./gmsmtk -algorithm SM2 -tcp server [-root cacert.pem] -cert server.pem -key server.key -cacert ca.pem -cakey ca.key [-ipport "8081"]
./gmsmtk -algorithm SM2 -tcp client [-cert client.pem] [-key client.key] [-ipport "127.0.0.1:8081"]
```

#### TLCP — print current external IP:
```bash
./gmsmtk -tcp ip
```

#### PEM encryption — key generation with password (SM4-CBC):
```bash
./gmsmtk -algorithm SM2 -pkey keygen -prv Private.pem -pub Public.pem -pass "minhaSenha"
```

#### PEM decryption — automatic prompt on read:
```bash
./gmsmtk -algorithm SM2 -pkey text -key Private.pem
# Passphrase: ********
```

#### Bin to Hex / Hex to Bin / Dump:
```bash
./gmsmtk -hex enc  < File.ext > File.hex
./gmsmtk -hex dec  < File.hex > File.ext
./gmsmtk -hex dump < File.ext
```

#### Random cryptographic key:
```bash
./gmsmtk -rand 128
./gmsmtk -rand 256
./gmsmtk -rand 512
```

---

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2026 Pedro F. Albanese — ALBANESE Research Lab.
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.

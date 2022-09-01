# :cn: GMSM Toolkit ☭
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gmsmtk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gmsmtk?status.png)](http://godoc.org/github.com/pedroalbanese/gmsmtk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/gmsmtk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/gmsmtk/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/gmsmtk)](https://goreportcard.com/report/github.com/pedroalbanese/gmsmtk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/gmsmtk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gmsmtk)](https://github.com/pedroalbanese/gmsmtk/releases)

Multi-purpose cross-platform cryptography tool for asymmetric/symmetric encryption, digital signature, cipher-based message authentication code (CMAC), hash digest, hash-based message authentication code (HMAC) and PBKDF2 function.

#### SM2/SM3/SM4 Chinese National Standard Algorithms:
* GM/T 0003-2012 - SM2 Public key algorithm 256-bit.
* GM/T 0004-2012 - SM3 Message digest algorithm. 256-bit hash value.
* GM/T 0002-2012 - SM4 128-bit block cipher with 128-bit key.
* GM/T 0001-2012 - ZUC Zu Chongzhi stream cipher 128/256-bit key.

#### Modes of operation:
* GCM: Galois/Counter Mode (AEAD) (default)
* CTR: Counter Mode
* OFB: Output Feedback Mode

#### Cryptographic Functions:
* Asymmetric Encryption
* Symmetric Encryption + AEAD mode
* Digital Signature (ECDSA)
* Shared Key Agreement (ECDH)
* Recusive Hash Digest + Check 
* CMAC (Cipher-based message authentication code)
* HMAC (Hash-based message authentication code)
* HKDF (HMAC-based key derivation function)
* PBKDF2 (Password-based key derivation function 2)
* TLS 1.2 (Transport Layer Security)

#### Non-Cryptographic Functions:
* Shred: Data sanitization method
* Bin to Hex/Hex to Bin string conversion
* Random Art (Public key Fingerprint)

### Usage 用法:
<pre> -bits int
       Bit-length. (for DERIVE, PBKDF2 and RAND) (default 128)
 -check string
       Check hashsum file. ('-' for STDIN)
 -crypt string
       Encrypt/Decrypt with SM4 symmetric block cipher.
 -digest string
       Target file/wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode/Decode [e|d] binary string to hex format and vice-versa.
 -hkdf
       HMAC-based key derivation function.
 -info string
       Associated data, additional info. (for HKDF and AEAD encryption)
 -iter int
       Iterations. (for PBKDF2 and SHRED commands) (default 1)
 -iv string
       Initialization vector. (for symmetric encryption)
 -key string
       Private/Public key, Secret key or Password.
 -keygen
       Generate asymmetric EC-SM2 keypair.
 -mac string
       Compute Cipher-based/Hash-based message authentication code.
 -mode string
       Mode of operation: GCM, CTR or OFB. (default "GCM")
 -pbkdf2
       Password-based key derivation function.
 -pkeyutl string
       DERIVE shared secret, ENCRYPT/DECRYPT with asymmetric algorithm.
 -pub string
       Remote's side public key/remote's side public IP/local port.
 -rand
       Generate random cryptographic key.
 -recursive
       Process directories recursively.
 -salt string
       Salt. (for PBKDF2 and HKDF commands)
 -shred string
       Files/Path/Wildcard to apply data sanitization method.
 -sign
       Sign with PrivateKey.
 -signature string
       Input signature. (for verification only)
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [dump|send|ip|listen|dial]
 -verify
       Verify with PublicKey.
 -version
       Print version information.</pre>

### Examples:
#### Asymmetric SM2 keypair generation:
<pre>./gmsmtk -keygen
</pre>
#### Derive shared secret key (SM2-ECDH):
<pre>./gmsmtk -pkeyutl derive_a -key $PrivateKeyB -pub $PublicKeyA [-info RandA;RandB] [-bits 64|128|256]
./gmsmtk -pkeyutl derive_b -key $PrivateKeyA -pub $PublicKeyB [-info RandA;RandB] [-bits 64|128|256]
</pre>
#### Derive shared secret key (ECDH Non-standard):
<pre>./gmsmtk -pkeyutl derive -key $PrivateKey -pub $PublicKey [-bits 64|128|256]
</pre>
#### Signature (SM2-ECDSA):
<pre>./gmsmtk -sign -key $PrivateKey < file.ext > sign.txt
sign=$(cat sign.txt)
./gmsmtk -verify -key $PublicKey -signature $sign < file.ext
echo $?
</pre>
#### Asymmetric encryption/decryption with SM2 algorithm:
<pre>./gmsmtk -pkeyutl enc -key $PublicKey < plaintext.ext > ciphertext.ext
./gmsmtk -pkeyutl dec -key $PrivateKey < ciphertext.ext > plaintext.ext
</pre>
#### Symmetric encryption/decryption with SM4 block cipher:
<pre>./gmsmtk -crypt enc -key $128bitkey < plaintext.ext > ciphertext.ext
./gmsmtk -crypt dec -key $128bitkey < ciphertext.ext > plaintext.ext
</pre>
#### CMAC-SM4 (cipher-based message authentication code):
<pre>./gmsmtk -mac cmac -key $64bitkey < file.ext
./gmsmtk -mac cmac -key $64bitkey -signature $128bitmac < file.ext
</pre>
#### Symmetric encryption/decryption with ZUC stream cipher:
<pre>./gmsmtk -crypt eea128 -key $128bitkey < plaintext.ext > ciphertext.ext
./gmsmtk -crypt eea128 -key $128bitkey < ciphertext.ext > plaintext.ext
</pre>
#### MAC-EIA3 (3GPP message authentication code):
<pre>./gmsmtk -mac eia128 -key $128bitkey < file.ext
./gmsmtk -mac eia128 -key $128bitkey -signature $32bitmac < file.ext
</pre>
#### SM3 hashsum (list):
<pre>./gmsmtk -digest "*.*" [-recursive]
</pre>
#### SM3 hashsum (single):
<pre>./gmsmtk -digest - < file.ext
</pre>
#### HMAC-SM3 (hash-based message authentication code):
<pre>./gmsmtk -mac hmac -key $128bitkey < file.ext
./gmsmtk -mac hmac -key $128bitkey -signature $256bitmac < file.ext
</pre>
#### PBKDF2 (password-based key derivation function 2):
<pre>./gmsmtk -pbkdf2 -key "pass" -iter 10000 -salt "salt"
</pre>
#### Note:
The PBKDF2 function can be combined with the CRYPT and HMAC commands:
<pre>./gmsmtk -crypt enc -pbkdf2 -key "pass" < plaintext.ext > ciphertext.ext
./gmsmtk -mac hmac -pbkdf2 -key "pass" -iter 10000 -salt "salt" < file.ext
</pre>
#### Shred (Data sanitization method, 25 iterations):
Prevents data recovery using standard recovery tools.
<pre>./gmsmtk -shred "keypair.ini" -iter 25
</pre>
#### Bin to Hex/Hex to Bin:
<pre>./gmsmtk -hex enc < File.ext > File.hex
./gmsmtk -hex dec < File.hex > File.ext
./gmsmtk -hex dump < File.ext
</pre>
#### TCP/IP w/ TLS Layer Dump/Send:
<pre>./gmsmtk -tcp ip > PublicIP.txt
./gmsmtk -tcp dump [-pub "8081"] > Token.jwt
./gmsmtk -tcp send [-pub "127.0.0.1:8081"] < Token.jwt
</pre>
#### TCP/IP w/ TLS Layer Listen/Dial:
<pre>./gmsmtk -tcp listen [-pub "8081"]
./gmsmtk -tcp dial [-pub "127.0.0.1:8081"]
</pre>
#### Random Art (Public Key Fingerprint):
<pre>./gmsmtk -key $pubkey
</pre>
## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2021 ALBANESE 研究实验室.

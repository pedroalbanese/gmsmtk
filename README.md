# GMSM Toolkit ☭
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gmsmtk/blob/master/LICENSE.md) 
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/gmsmtk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/gmsmtk/releases)
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gmsmtk?status.png)](http://godoc.org/github.com/pedroalbanese/gmsmtk)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/gmsmtk)](https://goreportcard.com/report/github.com/pedroalbanese/gmsmtk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/gmsmtk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gmsmtk)](https://github.com/pedroalbanese/gmsmtk/releases)

Multi purpose cross-platform cryptography tool for asymmetric/symmetric encryption, digital signature, cipher-based message authentication code (CMAC), hash digest, hash-based message authentication code (HMAC) and PBKDF2 function.

#### SM2/SM3/SM4 Chinese National Standard Algorithms:
* GM/T 0001-2012 - ZUC (Zu Chongzhi Cipher) stream cipher
* GM/T 0003-2012 - SM2 Public key algorithm 256-bit.
* GM/T 0004-2012 - SM3 Message digest algorithm. 256-bit hash value.
* GM/T 0002-2012 - SM4 Symmetric block cipher with 128-bit key.

#### Modes of operation:
* GCM: Galois/Counter Mode (AEAD)
* CTR: Counter Mode
* OFB: Output Feedback Mode

#### Cryptographic Functions:
* Asymmetric Encryption/Decryption
* Symmetric Encryption/Decryption
* Digital Signature (ECDSA)
* Shared Key Agreement (ECDH)
* Recusive Hash Digest + Check 
* CMAC (Cipher-based message authentication code)
* HMAC (Hash-based message authentication code)
* PBKDF2 (Password-based key derivation function 2)
* TLS 1.2 (Transport Layer Security)

### Usage 用法:
<pre> -bits int
       Bit-length. (for DERIVE, PBKDF2 and RAND) (default 128)
 -check string
       Check hashsum file. (- for STDIN)
 -crypt string
       Encrypt/Decrypt with SM4 symmetric block cipher.
 -derive string
       Derive shared secret key (SM2-ECDH) 128-bit default.
 -digest string
       Target file/wildcard to generate hashsum list. (- for STDIN)
 -hex string
       Encode/Decode [e|d] binary string to hex format and vice-versa.
 -iter int
       Iterations. (for PBKDF2 and SHRED commands) (default 1)
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
 -pub string
       Remote's side public key/remote's side public IP/PEM BLOCK.
 -rand
       Generate random cryptographic key.
 -recursive
       Process directories recursively.
 -salt string
       Salt. (for PBKDF2)
 -shred string
       Files/Path/Wildcard to apply data sanitization method.
 -sign
       Sign with PrivateKey.
 -signature string
       Input signature. (for verification only)
 -sm2dec
       Decrypt with asymmetric EC-SM2 Privatekey.
 -sm2enc
       Encrypt with asymmetric EC-SM2 Publickey.
 -tcp string
       Encrypted TCP/IP [dump|ip|send] Transfer Protocol.
 -verbose
       Verbose mode. (for CHECK command)
 -verify
       Verify with PublicKey.
 -version
       Print version information.</pre>

### Examples:
#### Asymmetric SM2 keypair generation:
<pre>./gmsmtk -keygen
</pre>
#### Derive shared secret key (SM2-ECDH):
<pre>./gmsmtk -derive a -key $PrivateKeyB -pub $PublicKeyA [-salt RandA;RandB] [-bits 64|128|256]
./gmsmtk -derive b -key $PrivateKeyA -pub $PublicKeyB [-salt RandA;RandB] [-bits 64|128|256]
</pre>
#### Derive shared secret key (ECDH Non-standard):
<pre>./gmsmtk -derive c -key $PrivateKey -pub $PublicKey [-bits 64|128|256]
</pre>
#### Signature (SM2-ECDSA):
<pre>./gmsmtk -sign -key $PrivateKey < file.ext > sign.txt
sign=$(cat sign.txt)
./gmsmtk -verify -key $PublicKey -signature $sign < file.ext
echo $?
</pre>
#### Asymmetric encryption/decryption with SM2 algorithm:
<pre>./gmsmtk -sm2enc -key $PublicKey < plaintext.ext > ciphertext.ext
./gmsmtk -sm2dec -key $PrivateKey < ciphertext.ext > plaintext.ext
</pre>
#### Symmetric encryption/decryption with SM4 block cipher:
<pre>./gmsmtk -crypt enc -key $128bitkey < plaintext.ext > ciphertext.ext
./gmsmtk -crypt dec -key $128bitkey < ciphertext.ext > plaintext.ext
</pre>
#### CMAC-SM4 (cipher-based message authentication code):
<pre>./gmsmtk -mac cmac -key $64bitkey < file.ext
</pre>
#### SM3 hashsum (list):
<pre>./gmsmtk -digest "*.*" [-recursive]
</pre>
#### SM3 hashsum (single):
<pre>./gmsmtk -digest - < file.ext
</pre>
#### HMAC-SM3 (hash-based message authentication code):
<pre>./gmsmtk -mac hmac -key $128bitkey < file.ext
</pre>
#### PBKDF2 (password-based key derivation function 2):
<pre>./gmsmtk -pbkdf2 -key "pass" -iter 10000 -salt "salt"
</pre>
#### Note:
The PBKDF2 function can be combined with the CRYPT and HMAC commands:
<pre>./gmsmtk -crypt -pbkdf2 -key "pass" < plaintext.ext > ciphertext.ext
./gmsmtk -mac hmac -pbkdf2 -key "pass" -iter 10000 -salt "salt" < file.ext
</pre>
#### Shred (Data sanitization method, 25 iterations):
Prevents data recovery using standard recovery tools.
<pre>./gmsmtk -shred "keypair.ini" -iter 25
</pre>
#### Bin to Hex/Hex to Bin:
<pre>echo somestring|./gmsmtk -hex enc
echo hexstring|./gmsmtk -hex dec
</pre>
#### TLS TCP/IP Layer Dump/Send:
<pre>./gmsmtk -tcp ip > PublicIP.txt
./gmsmtk -tcp dump [-pub "8081"] > Pubkey.txt
./gmsmtk -tcp send [-pub "127.0.0.1:8081"] < Pubkey.txt
</pre>
#### Random Art (Public Key Fingerprint):
<pre>./gmsmtk -key $pubkey
</pre>
## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2021 ALBANESE 研究实验室.

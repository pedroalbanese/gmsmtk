# GMSM Toolkit ☭
Multi purpose cross-platform cryptography tool for asymmetric/symmetric encryption, digital signature, cipher-based message authentication code (CMAC), hash digest, hash-based message authentication code (HMAC) and PBKDF2 function.

#### SM2/SM3/SM4 Chinese National Standard Algorithms:
* GM/T 0003-2012 - SM2 Public key algorithm 256-bit.
* GM/T 0004-2012 - SM3 Message digest algorithm. 256-bit hash value.
* GM/T 0002-2012 - SM4 Symmetric block cipher with 128-bit key.

#### Cryptographic Functions:
* Asymmetric Encryption/Decryption
* Symmetric Encryption/Decryption
* Digital Signature (ECDSA)
* Shared Key Agreement (ECDH)
* Recusive Hash Digest + Check 
* CMAC (Cipher-based message authentication code)
* HMAC (Hash-based message authentication code)
* PBKDF2 (Password-based key derivation function 2)

#### TODO:
  - [X] SM2 ECDH
  - [X] SM2 ECDSA
  - [X] SM2 Encryption
  - [x] SM3 HMAC
  - [x] SM3 Message Digest
  - [x] SM4 CMAC
  - [x] SM4 Encryption

### Usage:
<pre> -bits int
       Bit-length. (for DERIVE, PBKDF2 and RAND) (default 128)
 -check string
       Check hashsum file.
 -cmac
       Cipher-based message authentication code.
 -crypt
       Encrypt/Decrypt with SM4 block cipher.
 -decode
       Decode hex string to binary format.
 -derive string
       Derive shared secret key (SM2-ECDH) 128-bit default.
 -digest
       Compute single hashsum with SM3 algorithm.
 -hashsum string
       Target file/wildcard to generate hashsum list.
 -hex string
       Encode binary string to hex format and vice-versa.
 -hmac
       Hash-based message authentication code.
 -iter int
       Iterations. (for PBKDF2 and SHRED commands) (default 1)
 -key string
       Private/Public key, Secret key or Password.
 -keygen
       Generate asymmetric EC-SM2 keypair.
 -mode string
       Mode of operation: CTR or OFB. (default "CTR")
 -pbkdf2
       Password-based key derivation function.
 -pem string
       Encode hex string to pem format and vice-versa.
 -pub string
       Remote's side public key. (for shared key derivation)
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
       Encrypt with asymmetric EC-SM2 Publickey.
 -sm2enc
       Decrypt with asymmetric EC-SM2 Privatekey.
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
<pre>./gmsmtk -derive a -key $PrivateKeyB -pub $PublicKeyA -salt RandA;RandB [-bits 64|128|256]
./gmsmtk -derive b -key $PrivateKeyA -pub $PublicKeyB -salt RandA;RandB [-bits 64|128|256]
</pre>
#### Derive shared secret key (ECDH Non-standard):
<pre>./gmsmtk -derive c -key $PrivateKey -pub $PublicKey [-bits 64|128|256]
</pre>
#### Signature (SM2-ECDSA):
<pre>./gmsmtk -sign -key $PrivateKey < file.ext > sign.txt
sign=$(cat sign.txt)
./gmsmtk -verify -key $PublicKey -signature $sign < file.ext
</pre>
#### Asymmetric encryption/decryption with SM2 algorithm:
<pre>./gmsmtk -sm2enc -key $PublicKey < plaintext.ext > ciphertext.ext
./gmsmtk -sm2dec -key $PrivateKey < ciphertext.ext > plaintext.ext
</pre>
#### Symmetric encryption/decryption with SM4 block cipher:
<pre>./gmsmtk -crypt -key $128bitkey < plaintext.ext > ciphertext.ext
./gmsmtk -crypt -key $128bitkey < ciphertext.ext > plaintext.ext
</pre>
#### CMAC-SM4 (cipher-based message authentication code):
<pre>./gmsmtk -cmac -key $64bitkey < file.ext
</pre>
#### SM3 hashsum (list):
<pre>./gmsmtk -hashsum "*.*" [-recursive]
</pre>
#### SM3 hashsum (single):
<pre>./gmsmtk -digest < file.ext
</pre>
#### HMAC-SM3 (hash-based message authentication code):
<pre>./gmsmtk -hmac -key $128bitkey < file.ext
</pre>
#### PBKDF2 (password-based key derivation function 2):
<pre>./gmsmtk -pbkdf2 -key "pass" -iter 10000 -salt "salt"
</pre>
#### Note:
The PBKDF2 function can be combined with the CRYPT and HMAC commands:
<pre>./gmsmtk -crypt -pbkdf2 -key "pass" < plaintext.ext > ciphertext.ext
./gmsmtk -hmac -pbkdf2 -key "pass" -iter 10000 -salt "salt" < file.ext
</pre>

## License

This project is licensed under the ISC License.

##### Commercial Grade Reliability. Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.

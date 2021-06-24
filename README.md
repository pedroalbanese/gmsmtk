# GMSM Toolkit ☭
Multi purpose cross-platform cryptography tool for encryption / decryption, hash digest, hash-based message authentication code (HMAC) and PBKDF2 function.

#### SM3/SM4 Chinese National Standard Algoritms:
* GB/T 32918-2016 - SM2 Public key algorithm 256-bit.
* GM/T 0004-2012 - SM3 Message digest algorithm. 256-bit hash value.
* GB/T 32907-2016 - SM4 Symmetric block cipher with 128-bit key.

#### Cryptographic Functions:
* Asymmetric Encryption/Decryption
* Symmetric Encryption/Decryption
* Digital Signature
* Hash Digest 
* CMAC (Cipher-based message authentication code)
* HMAC (Hash-based message authentication code)
* PBKDF2 (Password-based key derivation function 2)

#### TODO:
  - [X] SM2 ECDSA
  - [X] SM2 Encryption
  - [x] SM3 HMAC
  - [x] SM3 Message Digest
  - [x] SM4 CMAC
  - [x] SM4 Encryption

### Usage:
<pre> -check string
       Check hashsum file.
 -cmac
       Cipher-based message authentication code.
 -crypt
       Encrypt/Decrypt with symmetric cipher SM4.
 -digest
       Compute single hashsum with SM3.
 -hashsum string
       Target file/wildcard to generate hashsum list.
 -hmac
       Hash-based message authentication code.
 -iter int
       Iterations. (for PBKDF2) (default 1024)
 -key string
       Private/Public key, Secret key or Password.
 -keygen
       Generate asymmetric key pair.
 -pbkdf2
       Password-based key derivation function.
 -rand
       Generate random 128-bit cryptographic key.
 -recursive
       Process directories recursively.
 -salt string
       Salt. (for PBKDF2)
 -short
       Generate 64-bit key. (for RAND and PBKDF2 command)
 -sign
       Sign with PrivateKey.
 -signature string
       String to Encrypt/Decrypt.
 -sm2dec
       Decrypt with SM2 PrivateKey.
 -sm2enc
       Encrypt with SM2 Publickey.
 -verbose
       Verbose mode. (for CHECK command)
 -verify
       Verify with PublicKey.</pre>

### Examples:
#### Encryption/decryption with SM4 symmetric block cipher:
<pre>./gmsmtk -crypt -key $128bitkey < plaintext.ext > ciphertext.ext
./gmsmtk -crypt -key $128bitkey < ciphertext.ext > plaintext.ext
</pre>
#### SM3 hashsum (list):
<pre>./gmsmtk -hashsum "*.*" [-rec]
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
##### Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.

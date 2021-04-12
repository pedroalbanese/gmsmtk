# GMSM Toolkit ☭
Multi purpose cross-platform cryptography tool for encryption / decryption, hash digest, hash-based message authentication code (HMAC) and PBKDF2 function.

#### SM3/SM4 Chinese National Standard Algoritms:
* GM/T 0004-2012 - SM3 Message digest algorithm. 256-bit hash value.
* GB/T 32907-2016 - SM4 Symmetric block cipher with 128-bit key.

#### Cryptographic Functions:
* Symmetric Encryption/Decryption
* Hash Digest 
* HMAC (Hash-based message authentication code)
* PBKDF2 (Password-based key derivation function 2)

#### TODO:
  - [ ] SM2 ECDSA
  - [ ] SM2 Encryption
  - [x] SM3 HMAC
  - [x] SM3 Message Digest
  - [x] SM4 Encryption

### Usage:
<pre> -check string
       Check hashsum file.
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
       Secret key/Password.
 -pbkdf2
       Password-based key derivation function.
 -rand
       Generate random 128-bit cryptographic key.
 -rec
       Process directories recursively.
 -salt string
       Salt. (for PBKDF2)
 -verb
       Verbose mode. (for CHECK command)</pre>

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
#### My project branch has been adjusted to suit my company,Maybe not for you.
##### Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.

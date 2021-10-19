# feistel-cipher-sample
Sample Implementation for Feistel Cipher for teaching purposes

## Requirements

Java 11

## Building

```
$ cd src

$ javac es/usj/crypto/cipher/FeistelCipherApp.java
```

## Running

```
$ cd src

$ java -cp . es.usj.crypto.cipher.FeistelCipherApp

Plaintext (ascii)   : Crypto
Plaintext (binary)  : 010000110111001001111001011100000111010001101111
-------------------------------------
Ciphertext (binary) : 001101100001011100101101001101010111010101011110
Ciphertext (ascii)  : 6-5u^
-------------------------------------
Deciphered (binary) : 010000110111001001111001011100000111010001101111
Deciphered (ascii)  : Crypto
```

*Plaintext* may be specified as first argument by using the command line. For instance, following command is encrypting sentence "Alice in Wonderland":

```
$ java -cp . es.usj.crypto.cipher.FeistelCipherApp "Alice in Wonderland"
```

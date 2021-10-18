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
Plaintext (binary)  : 10000110111001001111001011100000111010001101111
-------------------------------------
Ciphertext (binary) : 111000101110010010010111101001001010110011111111
Ciphertext (ascii)  : âä¤¬ÿ
-------------------------------------
Deciphered (binary) : 10000110111001001111001011100000111010001101111
Deciphered (ascii)  : Crypto
```

*Plaintext* may be specified as first argument by using the command line. For instance, following command is encrypting sentence "Alice in Wonderland":

```
$ java -cp . es.usj.crypto.cipher.FeistelCipherApp "Alice in Wonderland"
```

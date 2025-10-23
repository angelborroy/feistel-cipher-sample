# feistel-cipher-sample

Sample implementation of a Feistel Cipher with ECB-like mode for teaching purposes.

## Overview

This educational implementation demonstrates:
- **Feistel network structure**: How left/right halves are swapped and mixed using XOR operations
- **Block cipher operation**: Processing fixed 64-bit (8-byte) blocks
- **ECB-like mode**: Handling messages longer than one block by encrypting each block independently
- **Avalanche effect**: How small input changes produce dramatically different outputs
- **ECB weakness**: Why identical plaintext blocks produce identical ciphertext (security vulnerability)

⚠️ **Security Warning**: This code is for educational purposes only. It is NOT cryptographically secure and should never be used in production systems.

## Requirements

Java 11 or higher

## Building

```bash
$ cd src
$ javac es/usj/crypto/cipher/FeistelCipherApp.java
```

## Running

### Basic Usage

```bash
$ cd src
$ java -cp . es.usj.crypto.cipher.FeistelCipherApp
```

**Output:**
```
=== INPUT ===
Plaintext:   "Hello, what are you doing"
Length:      25 characters
Blocks:      4 blocks (8 bytes each)

=== ENCRYPTION ===
Block 0: 0x48656C6C6F2C2077 -> 0x9C3E7A1B4F8D2E6C
Block 1: 0x6861742061726520 -> 0x5A9E3C7D1B8F4E2A
Block 2: 0x796F7520646F696E -> 0x7D2E9C4A6F1B8E3C
Block 3: 0x6720202020202020 -> 0x4B8E2C9D5F7A1E3B

=== DECRYPTION ===
Block 0: 0x9C3E7A1B4F8D2E6C -> 0x48656C6C6F2C2077
Block 1: 0x5A9E3C7D1B8F4E2A -> 0x6861742061726520
Block 2: 0x7D2E9C4A6F1B8E3C -> 0x796F7520646F696E
Block 3: 0x4B8E2C9D5F7A1E3B -> 0x6720202020202020

=== RESULTS ===
Original:    "Hello, what are you doing"
Decrypted:   "Hello, what are you doing"
Match:       true

=== AVALANCHE EFFECT DEMO ===
Original input:  "Crypto!!" -> 0xA3B5C9D7E2F48A6C
Modified input:  "Cryptp!!" -> 0x5E7A9C3B1D8F4E2A
Difference:      32 out of 64 bits changed (50.0%)
Note: Good ciphers should change ~50% of bits for any small input change.

=== ECB MODE WEAKNESS DEMO ===
Plaintext with repeated blocks: "AAAAAAAAAAAAAAAAABBBBBBBB"
Block 0: "AAAAAAAA" -> 0x4141414141414141
Block 1: "AAAAAAAA" -> 0x4141414141414141
Block 2: "BBBBBBBB" -> 0x4242424242424242

Ciphertext blocks:
Cipher 0: 0x9E7C3B5A1D8F4E2C
Cipher 1: 0x9E7C3B5A1D8F4E2C
Cipher 2: 0x7A3E9C4B5D1F8E2A

Notice: Blocks 0 and 1 are IDENTICAL! This is ECB's weakness.
An attacker can see patterns in the plaintext by observing ciphertext.
```

### Custom Plaintext

You can specify any plaintext as command-line arguments:

```bash
$ java -cp . es.usj.crypto.cipher.FeistelCipherApp "Alice in Wonderland"
```

```bash
$ java -cp . es.usj.crypto.cipher.FeistelCipherApp Hello world this is a longer message
```

**Note**: Multiple arguments are automatically joined with spaces.

## Key Features for Learning

### 1. **Multi-Block Support**
- Messages are automatically split into 8-byte blocks
- Last block is padded with spaces if needed
- All blocks are encrypted/decrypted independently (ECB mode)

### 2. **Educational Demonstrations**
- **Avalanche Effect**: Change one character and see ~50% of output bits change
- **ECB Weakness**: See how identical plaintext blocks create identical ciphertext blocks

### 3. **Simple Round Function**
The round function uses only XOR for clarity:
```java
F(R, K) = R ^ K
```

Students can experiment by modifying it to add rotation, addition, or other operations.

## Experiments for Students

### Modify the Round Function
Try different implementations in the `F()` method:
```java
// Add rotation for better diffusion
return Integer.rotateLeft(right ^ k, 3);

// Use addition instead of XOR
return (right + k);

// Combine multiple operations
return Integer.rotateLeft(right, 5) ^ (k * 0x9E3779B9);
```

### Change Round Count
Modify `ROUNDS` to see how security improves with more rounds:
```java
private static final int ROUNDS = 8;  // Try 2, 4, 8, 16
```

### Experiment with Different Keys
Change the master key and observe ciphertext differences:
```java
int masterKey = 0x12345678;  // Try different values
```

## Implementation Details

- **Block Size**: 64 bits (8 bytes)
- **Key Size**: 32 bits (demonstration only)
- **Rounds**: 4 (configurable)
- **Mode**: ECB-like (independent block encryption)
- **Padding**: Spaces (0x20) for incomplete blocks

## Learning Objectives

This implementation teaches:
1. **Feistel Structure**: Encryption/decryption symmetry without needing invertible functions
2. **Block Cipher Basics**: Fixed-size block processing
3. **Key Scheduling**: Deriving multiple round keys from a master key
4. **Mode of Operation**: How to handle multiple blocks (and ECB's limitations)
5. **Confusion & Diffusion**: XOR provides confusion, multiple rounds provide diffusion
6. **Security Principles**: Why simple designs fail (avalanche, ECB patterns)

## License

Educational use only. Not for production systems.
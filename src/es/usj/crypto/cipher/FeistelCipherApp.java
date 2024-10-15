package es.usj.crypto.cipher;

import java.util.List;

/**
 * Sample implementation for Feistel Network using AND operation as Function.
 *
 * This implementation is for educational purposes.
 */
public class FeistelCipherApp {

    // Default plaintext when none is provided as a program argument
    private static String plaintext = "Crypto";

    public static void main(String... args) {
        // Use command-line argument as plaintext if available
        if (args.length > 0 && args[0] != null) {
            plaintext = args[0];
        }
        System.out.println("Plaintext (ascii)   : " + plaintext);

        // Convert plaintext to binary string (padded to 8-bit boundaries)
        String binaryInput = padTo8BitBlocks(asciiToBinary(plaintext));
        System.out.println("Plaintext (binary)  : " + binaryInput);
        System.out.println("-------------------------------------");

        // Encrypt the binary input using Feistel encryption
        String binaryOutput = processInBlocks(binaryInput, FeistelCipher::encrypt);
        System.out.println("Ciphertext (binary) : " + binaryOutput);

        // Convert binary ciphertext to ASCII
        String ciphertext = binaryToAscii(binaryOutput);
        System.out.println("Ciphertext (ascii)  : " + ciphertext);
        System.out.println("-------------------------------------");

        // Decrypt the binary ciphertext using Feistel decryption
        String decryptedBinary = processInBlocks(binaryOutput, FeistelCipher::decrypt);
        System.out.println("Deciphered (binary) : " + decryptedBinary);

        // Convert decrypted binary back to ASCII
        String decryptedText = binaryToAscii(decryptedBinary);
        System.out.println("Deciphered (ascii)  : " + decryptedText);
    }

    /**
     * Converts an ASCII string to its binary representation.
     */
    private static String asciiToBinary(String asciiStr) {
        StringBuilder binaryStr = new StringBuilder();
        for (char ch : asciiStr.toCharArray()) {
            String binaryChar = String.format("%8s", Integer.toBinaryString(ch)).replace(' ', '0');
            binaryStr.append(binaryChar);
        }
        return binaryStr.toString();
    }

    /**
     * Converts a binary string back to ASCII.
     */
    private static String binaryToAscii(String binaryStr) {
        StringBuilder asciiStr = new StringBuilder();
        for (int i = 0; i < binaryStr.length(); i += 8) {
            String byteStr = binaryStr.substring(i, i + 8);
            asciiStr.append((char) Integer.parseInt(byteStr, 2));
        }
        return asciiStr.toString();
    }

    /**
     * Pads a binary string to 8-bit block size.
     */
    private static String padTo8BitBlocks(String binaryStr) {
        int paddingLength = 8 - (binaryStr.length() % 8);
        return "0".repeat(paddingLength) + binaryStr;
    }

    /**
     * Processes binary strings in 8-bit blocks with the provided function.
     */
    private static String processInBlocks(String binaryInput, FeistelOperation operation) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < binaryInput.length(); i += 8) {
            result.append(operation.apply(binaryInput.substring(i, i + 8)));
        }
        return result.toString();
    }

    /**
     * Functional interface for Feistel operations (encrypt/decrypt).
     */
    @FunctionalInterface
    private interface FeistelOperation {
        String apply(String input);
    }

    /**
     * Implementation of the Feistel cipher.
     */
    static class FeistelCipher {

        private static final int ROUNDS = 4;
        private static final List<String> KEYS = List.of(
                "1110", "0100", "1101", "0001",
                "0010", "1111", "1011", "1000",
                "0011", "1010", "0110", "1100",
                "0101", "1001", "0000", "0111"
        );

        /**
         * Encrypts a block of 8 bits using Feistel network.
         */
        public static String encrypt(String block) {
            String left = block.substring(0, 4);
            String right = block.substring(4);

            for (int i = 0; i < ROUNDS; i++) {
                String newRight = XOR(left, F(right, i));
                left = right;
                right = newRight;
            }

            return left + right;
        }

        /**
         * Decrypts a block of 8 bits using Feistel network.
         */
        public static String decrypt(String block) {
            String left = block.substring(0, 4);
            String right = block.substring(4);

            for (int i = 0; i < ROUNDS; i++) {
                String newLeft = XOR(right, F(left, ROUNDS - i - 1));
                right = left;
                left = newLeft;
            }

            return left + right;
        }

        /**
         * Feistel function F, applying AND with the subkey.
         */
        private static String F(String halfBlock, int round) {
            return AND(halfBlock, KEYS.get(round % KEYS.size()));
        }

        /**
         * Applies AND operation on two binary strings.
         */
        private static String AND(String a, String b) {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < a.length(); i++) {
                result.append((a.charAt(i) - '0') & (b.charAt(i) - '0'));
            }
            return result.toString();
        }

        /**
         * Applies XOR operation on two binary strings.
         */
        private static String XOR(String a, String b) {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < a.length(); i++) {
                result.append((a.charAt(i) - '0') ^ (b.charAt(i) - '0'));
            }
            return result.toString();
        }
    }
}

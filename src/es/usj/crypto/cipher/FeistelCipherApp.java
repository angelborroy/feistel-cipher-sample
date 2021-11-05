package es.usj.crypto.cipher;

import java.util.List;

/**
 * Sample implementation for Feistel Network using OR operation as Function.
 *
 * This code has been only developed for teaching purposes (!)
 *
 * Built from source code available in
 * https://github.com/AlaaSallamI/Feistel-Cipher-in-Java/blob/master/FeistelCipher.java
 *
 */
public class FeistelCipherApp {

    // Input plaintext
    private static final String binaryInput = "01010101";

    public static void main(String... args) {

        System.out.println("Plaintext (binary)  : " + binaryInput);

        // Apply Feistel encryption in blocks of 8 bits
        StringBuilder binaryOutput = new StringBuilder();
        binaryOutput.append(FeistelCipher.encrypt(binaryInput));
        System.out.println("Ciphertext (binary) : " + binaryOutput);

        // Apply Feistel decryption in blocks of 8 bits
        StringBuilder decryptedBinary = new StringBuilder();
        decryptedBinary.append(FeistelCipher.decrypt(binaryOutput.toString()));
        System.out.println("Deciphered (binary) : " + decryptedBinary);

    }

    /**
     * Sample implementation for Feistel Network:
     * - Blocks of 8 bits
     * - 3 rounds of the algorithm (by default)
     * - Function apply OR to right bits and XOR operation to left bits
     * - Key space based in a map of 16 blocks (4 bits)
     */
    static class FeistelCipher {

        // Number of rounds of the algorithm
        static int roundCount = 3;

        // Default Key Space
        static List<String> keys = List.of(
            "1010", "0010", "1100");

        /**
         * Get ciphered message from a plaintext
         * @param message Plaintext to be ciphered expressed as binary string
         * @return Ciphertext for the plaintext expressed as binary string
         */
        public static String encrypt(String message) {

            // Divide the message in blocks of 4 bits
            int messageMid = message.length() / 2;
            String left = message.substring(0, messageMid);
            String right = message.substring(messageMid);

            // Apply the algorithm for a number of rounds
            for (int roundIndex = 0; roundIndex < roundCount; roundIndex++) {
                // Preserve original RIGHT part
                String temp = right;
                // Calculate the 4 bits to be applied to LEFT part (Function)
                String functionText = OR(right, getSubKey(roundIndex));
                // Apply XOR function in LEFT part and switch the result to the RIGHT
                right = XOR(left, functionText);
                // Switch original RIGHT part to the LEFT
                left = temp;
            }
            return left + "" + right;
        }

        /**
         * Get plaintext message from a ciphertext
         * @param message Ciphertext to be decrypted expressed as binary string
         * @return Plaintext for the ciphertext expressed as binary string
         */
        public static String decrypt(String message) {

            // Divide the message in blocks of 4 bits
            int messageMid = message.length() / 2;
            String left = message.substring(0, messageMid);
            String right = message.substring(messageMid);

            // Apply the algorithm for a number of rounds
            for (int roundIndex = 0; roundIndex < roundCount; roundIndex++) {
                // Preserve original LEFT part
                String temp = left;
                // Calculate the 4 bits to be applied to RIGHT part (Function, reverse scheduled!)
                String functionText = OR(left, getSubKey(roundCount - roundIndex - 1));
                // Apply XOR function in RIGHT part and switch the result to the LEFT
                left = XOR(right, functionText);
                // Switch original LEFT part to the RIGHT
                right = temp;
            }

            return left + "" + right;
        }

        /**
         * Get a key from the key space
         * @param roundIndex current round index
         * @return 4-bits binary key
         */
        private static String getSubKey(int roundIndex) {
            return keys.get(roundIndex);
        }

        /**
         * Apply OR (|) operation to every bit in left and right binary strings
         */
        private static String OR(String left, String right) {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < left.length(); i++) {
                // Convert the char to number subtracting char '0'
                stringBuilder.append((left.charAt(i) - '0') | (right.charAt(i) - '0'));
            }
            return stringBuilder.toString();
        }

        /**
         * Apply XOR (^) operation to every bit in left and right binary strings
         */
        private static String XOR(String left, String right) {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < left.length(); i++) {
                // Convert the char to number subtracting char '0'
                stringBuilder.append((left.charAt(i) - '0') ^ (right.charAt(i) - '0'));
            }
            return stringBuilder.toString();
        }

    }
}

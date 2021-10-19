package es.usj.crypto.cipher;

import java.math.BigInteger;
import java.util.List;

/**
 * Sample implementation for Feistel Network.
 * - Plaintext can be also passed as main args[0]
 *
 * This code has been only developed for teaching purposes (!)
 *
 * Built from source code available in
 * https://github.com/AlaaSallamI/Feistel-Cipher-in-Java/blob/master/FeistelCipher.java
 *
 */
public class FeistelCipherApp {

    private static String plaintext = "Crypto";

    public static void main(String... args) throws Exception {

        // Take plaintext as first program argument when exists
        if (args.length > 0 && args[0] != null) {
            plaintext = args[0];
        }
        System.out.println("Plaintext (ascii)   : " + plaintext);

        // Convert ASCII Input string in binary string
        String binaryInput = asciiToBinary(plaintext);
        // Add 0 bits in the beginning to complete 8-bit blocks
        for (int i = 0; i < (binaryInput.length() % 8); i++) {
            binaryInput = "0" + binaryInput;
        }
        System.out.println("Plaintext (binary)  : " + binaryInput);
        System.out.println("-------------------------------------");

        // Apply Feistel encryption in blocks of 8 bits
        String binaryOutput = "";
        int index = 0;
        while (index < binaryInput.length()) {
            binaryOutput += FeistelCipher.encrypt(binaryInput.substring(index, index + 8));
            index += 8;
        }
        System.out.println("Ciphertext (binary) : " + binaryOutput);

        // Convert Binary Output string in ASCII
        String ciphertext = binaryToAscii(binaryOutput);
        System.out.println("Ciphertext (ascii)  : " + ciphertext);
        System.out.println("-------------------------------------");

        // Apply Feistel decryption in blocks of 8 bits
        String decryptedBinary = "";
        index = 0;
        while (index < binaryOutput.length()) {
            decryptedBinary += FeistelCipher.decrypt(binaryOutput.substring(index, index + 8));
            index += 8;
        }
        System.out.println("Deciphered (binary) : " + decryptedBinary);

        // Convert Binary Output to string in ASCII
        String decrypted = binaryToAscii(decryptedBinary);
        System.out.println("Deciphered (ascii)  : " + decrypted);

    }

    /**
     * Convert text string in ASCII encoding to binary string
     * @param asciiStr Text string in ASCII encoding
     * @return binary string representing the asciiStr
     */
    private static String asciiToBinary(String asciiStr) {
        char[] chars = asciiStr.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char ch : chars) {
            hex.append(Integer.toHexString(ch));
        }
        return new BigInteger(hex.toString(), 16).toString(2);
    }

    /**
     * Convert binary string to text string in ASCII encoding
     * @param binaryStr Binary string
     * @return Text string in ASCII encoding representing the binaryStr
     */
    private static String binaryToAscii(String binaryStr) {
        String hexStr = new BigInteger(binaryStr, 2).toString(16);
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * Sample implementation for Feistel Network:
     * - Blocks of 8 bits
     * - 4 rounds of the algorithm (by default)
     * - Function apply AND to right bits and XOR operation to left bits
     * - Key space based in a map of 16 blocks (4 bits)
     */
    static class FeistelCipher {

        // Number of rounds of the algorithm
        static int roundCount = 4;

        // Key space
        static List<String> keys = List.of(
            "1110", "0100", "1101", "0001",
            "0010", "1111", "1011", "1000",
            "0011", "1010", "0110", "1100",
            "0101", "1001", "0000", "0111");

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
                // Calculate the 4 bits to be applied to LEFT part
                String functionText = AND(right, getSubKey(roundIndex));
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
                // Calculate the 4 bits to be applied to RIGHT part (reverse scheduled)
                String functionText = AND(left, getSubKey(roundCount - roundIndex - 1));
                // Apply XOR function in RIGHT part and switch the result to the LEFT
                left = XOR(right, functionText);
                // Switch original LEFT part to the RIGHT
                right = temp;
            }

            return left + "" + right;
        }

        /**
         * Get a key from the key space modulo 16
         * @param roundIndex current round index
         * @return 4-bits binary key
         */
        private static String getSubKey(int roundIndex) {
            return keys.get(roundIndex % 16);
        }

        /**
         * Apply AND (&) operation to every bit in left and right binary strings
         */
        private static String AND(String left, String right) {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < left.length(); i++) {
                // Convert the char to number subtracting char '0'
                stringBuilder.append((left.charAt(i) - '0') & (right.charAt(i) - '0'));
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

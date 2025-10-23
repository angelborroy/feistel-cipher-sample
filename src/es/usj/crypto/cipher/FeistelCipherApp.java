package es.usj.crypto.cipher;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal Feistel network demo with ECB-like mode (NOT secure).
 *
 * Feistel Structure:
 *
 *   L₀   R₀
 *   |     |
 *   |    [F]-- K₀
 *   |     |
 *   └--⊕--┘
 *   |  |
 *   R₁ L₁  (swap)
 *
 * Goal
 * ----
 * Show the structure of a Feistel cipher in a compact, readable way:
 *  - Messages are split into 64-bit blocks (8 bytes each).
 *  - Each block is split into left and right 32-bit halves.
 *  - Each round applies a simple round function F to the right half and a subkey,
 *    then mixes the result into the left half with XOR, and finally swaps halves.
 *  - Decryption uses the same steps but applies subkeys in reverse order.
 *  - Multiple blocks are encrypted independently (ECB-like mode).
 *
 * Why this helps learning
 * -----------------------
 *  - Integer bit operations match how real ciphers work.
 *  - Exactly one subkey per round keeps round-to-key mapping obvious.
 *  - ECB mode shows how block ciphers handle messages longer than one block.
 *  - Simple structure makes data flow easy to follow and modify.
 *
 * Security warning
 * ----------------
 * This code is only for education. ECB mode reveals patterns in plaintext and is
 * insecure. The round function and key schedule are also not secure.
 * DO NOT USE IN PRODUCTION.
 */
public class FeistelCipherApp {

    // Keep rounds low for visibility in class. Feel free to try 8 or 16 in experiments.
    private static final int ROUNDS = 4;

    // Set to true to see each round's state during encryption
    private static final boolean DEBUG = false;

    public static void main(String[] args) {
        // Read plaintext from command line or use a default.
        String plaintext = (args.length > 0) ? String.join(" ", args) : "Hello, what are you doing";
        // A fixed 32-bit demo key. For experiments, change this value.
        int masterKey = 0xA3B1_5C97;

        // 1) Produce exactly one 32-bit subkey per round.
        int[] subkeys = deriveSubkeys(masterKey, ROUNDS);

        // 2) Convert the plaintext into multiple 64-bit blocks (ECB-like mode).
        long[] blocks = packToBlocks(plaintext);

        System.out.println("=== INPUT ===");
        System.out.println("Plaintext:   \"" + plaintext + "\"");
        System.out.println("Length:      " + plaintext.length() + " characters");
        System.out.println("Blocks:      " + blocks.length + " blocks (8 bytes each)");

        // 3) Encrypt all blocks.
        System.out.println("\n=== ENCRYPTION ===");
        long[] cipherBlocks = new long[blocks.length];
        for (int i = 0; i < blocks.length; i++) {
            if (DEBUG) System.out.println("\n--- Block " + i + " ---");
            cipherBlocks[i] = encryptBlock(blocks[i], subkeys);
            System.out.println("Block " + i + ": 0x" + toHex64(blocks[i]) + " -> 0x" + toHex64(cipherBlocks[i]));
        }

        // 4) Decrypt all blocks to recover the original data.
        System.out.println("\n=== DECRYPTION ===");
        long[] decryptedBlocks = new long[cipherBlocks.length];
        for (int i = 0; i < cipherBlocks.length; i++) {
            if (DEBUG) System.out.println("\n--- Block " + i + " ---");
            decryptedBlocks[i] = decryptBlock(cipherBlocks[i], subkeys);
            System.out.println("Block " + i + ": 0x" + toHex64(cipherBlocks[i]) + " -> 0x" + toHex64(decryptedBlocks[i]));
        }

        // 5) Reconstruct the plaintext from decrypted blocks.
        String recovered = unpackFromBlocks(decryptedBlocks, plaintext.length());

        System.out.println("\n=== RESULTS ===");
        System.out.println("Original:    \"" + plaintext + "\"");
        System.out.println("Decrypted:   \"" + recovered + "\"");
        System.out.println("Match:       " + plaintext.equals(recovered));

        // 6) Demonstrate avalanche effect: one character change causes dramatic output change.
        demonstrateAvalancheEffect(subkeys);

        // 7) Demonstrate ECB weakness: identical blocks produce identical ciphertext.
        demonstrateECBWeakness(subkeys);
    }

    /**
     * Encrypt one 64-bit block with a Feistel network.
     *
     * Implementation details
     * ----------------------
     * - Split the 64-bit input into two 32-bit halves L and R.
     * - For each round r:
     *     newL = R
     *     newR = L ^ F(R, subkeys[r])
     *     L = newL; R = newR
     *   This is the classic Feistel update. The swap is built into these assignments.
     * - Join L and R back into a 64-bit value and return it.
     *
     * Why this works
     * --------------
     * Because only XOR and swapping are used, and because F never needs to be invertible,
     * the Feistel structure guarantees that decryption is possible by applying subkeys in reverse.
     */
    public static long encryptBlock(long block64, int[] subkeys) {
        // Extract left and right 32-bit halves.
        int L = (int) (block64 >>> 32);
        int R = (int) (block64 & 0xFFFF_FFFF);

        if (DEBUG) printRound(0, L, R);

        // Apply rounds in forward order for encryption.
        for (int r = 0; r < subkeys.length; r++) {
            // Save next left as current right (swap part).
            int newL = R;
            // Mix: left becomes previous left XOR roundFunction(right, subkey)
            int newR = L ^ F(R, subkeys[r]);
            // Advance halves.
            L = newL;
            R = newR;

            if (DEBUG) printRound(r + 1, L, R);
        }

        // After the last round, the typical Feistel swap effect is already accounted for.
        return join64(L, R);
    }

    /**
     * Decrypt one 64-bit block with a Feistel network.
     *
     * Implementation details
     * ----------------------
     * - Same update shape as encryption but iterate subkeys in reverse order.
     * - Swapping and XOR symmetry restore the original halves.
     *
     * Mental model
     * ------------
     * Each round of decryption cancels one round of encryption because:
     *   L_next = R_prev
     *   R_next = L_prev ^ F(R_prev, K_r)
     * When you process in reverse with the same equations, you undo the previous step.
     */
    public static long decryptBlock(long block64, int[] subkeys) {
        // Extract left and right 32-bit halves.
        int L = (int) (block64 >>> 32);
        int R = (int) (block64 & 0xFFFF_FFFF);

        if (DEBUG) printRound(subkeys.length, L, R);

        // Apply rounds in reverse order for decryption.
        for (int r = subkeys.length - 1; r >= 0; r--) {
            // Inverse step mirrors the encrypt update with swapped roles.
            int newR = L;                   // undo the previous swap
            int newL = R ^ F(L, subkeys[r]); // undo the previous XOR mix
            L = newL;
            R = newR;

            if (DEBUG) printRound(r, L, R);
        }

        return join64(L, R);
    }

    /**
     * Round function F: combine the right half with the subkey.
     *
     * Implementation choice
     * ---------------------
     * F(R, K) = R ^ K
     * - Simple XOR shows that F doesn't need to be invertible (key Feistel property).
     * - XOR with the subkey injects key material (provides confusion).
     *
     * For classroom experiments
     * -------------------------
     * Try variants and observe ciphertext changes:
     *   - return Integer.rotateLeft(right ^ k, 3);  // add diffusion
     *   - return (right + k);   // addition instead of XOR
     *   - return (right ^ k) * 0x9E3779B9;  // multiply for mixing
     */
    private static int F(int right, int k) {
        return right ^ k;
    }

    /**
     * Toy key schedule that derives one 32-bit subkey per round from a 32-bit master key.
     *
     * Implementation details
     * ----------------------
     * - XOR the master key with a round-dependent constant.
     * - The constant (0x9E3779B9) is derived from the golden ratio and ensures good mixing.
     * - This is not secure. It is only to create visibly different subkeys for learning.
     *
     * Why not a fixed array of keys
     * -----------------------------
     * Round count is 4, so produce exactly 4 subkeys. One subkey per round keeps mapping obvious:
     *   round 0 -> K[0], round 1 -> K[1], etc.
     */
    private static int[] deriveSubkeys(int masterKey, int rounds) {
        int[] ks = new int[rounds];
        for (int i = 0; i < rounds; i++) {
            // Mix master key with round-dependent constant (golden ratio * 2^32)
            ks[i] = masterKey ^ (i * 0x9E3779B9);
        }
        return ks;
    }

    /**
     * Print the state of left and right halves at a given round.
     * Helps students visualize the Feistel structure in action.
     */
    private static void printRound(int round, int L, int R) {
        System.out.printf("Round %d: L=%08X  R=%08X%n", round, L, R);
    }

    /**
     * Count how many bits differ between two 64-bit values.
     * Used to demonstrate the avalanche effect.
     */
    private static int countDifferentBits(long a, long b) {
        return Long.bitCount(a ^ b);
    }

    /**
     * Demonstrate avalanche effect with a simple example.
     */
    private static void demonstrateAvalancheEffect(int[] subkeys) {
        System.out.println("\n=== AVALANCHE EFFECT DEMO ===");
        String plain1 = "Crypto!!";
        String plain2 = "Cryptp!!";  // Changed 'o' to 'p'

        long block1 = pack8(plain1);
        long block2 = pack8(plain2);
        long cipher1 = encryptBlock(block1, subkeys);
        long cipher2 = encryptBlock(block2, subkeys);

        int bitsDifferent = countDifferentBits(cipher1, cipher2);
        double percentage = (bitsDifferent * 100.0) / 64;

        System.out.println("Original input:  \"" + plain1 + "\" -> 0x" + toHex64(cipher1));
        System.out.println("Modified input:  \"" + plain2 + "\" -> 0x" + toHex64(cipher2));
        System.out.printf("Difference:      %d out of 64 bits changed (%.1f%%)%n", bitsDifferent, percentage);
        System.out.println("Note: Good ciphers should change ~50% of bits for any small input change.");
    }

    /**
     * Demonstrate ECB mode weakness: identical plaintext blocks produce identical ciphertext.
     */
    private static void demonstrateECBWeakness(int[] subkeys) {
        System.out.println("\n=== ECB MODE WEAKNESS DEMO ===");
        String repeated = "AAAAAAAA" + "AAAAAAAA" + "BBBBBBBB";  // Two identical blocks, one different

        long[] blocks = packToBlocks(repeated);
        System.out.println("Plaintext with repeated blocks: \"" + repeated + "\"");
        System.out.println("Block 0: \"" + repeated.substring(0, 8) + "\" -> 0x" + toHex64(blocks[0]));
        System.out.println("Block 1: \"" + repeated.substring(8, 16) + "\" -> 0x" + toHex64(blocks[1]));
        System.out.println("Block 2: \"" + repeated.substring(16, 24) + "\" -> 0x" + toHex64(blocks[2]));

        long cipher0 = encryptBlock(blocks[0], subkeys);
        long cipher1 = encryptBlock(blocks[1], subkeys);
        long cipher2 = encryptBlock(blocks[2], subkeys);

        System.out.println("\nCiphertext blocks:");
        System.out.println("Cipher 0: 0x" + toHex64(cipher0));
        System.out.println("Cipher 1: 0x" + toHex64(cipher1));
        System.out.println("Cipher 2: 0x" + toHex64(cipher2));
        System.out.println("\nNotice: Blocks 0 and 1 are IDENTICAL! This is ECB's weakness.");
        System.out.println("An attacker can see patterns in the plaintext by observing ciphertext.");
    }

    // ===================== Packing / Unpacking helpers ======================

    /**
     * Pack a string into multiple 64-bit blocks (8 bytes each).
     * The last block is padded with spaces if needed.
     */
    private static long[] packToBlocks(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        int blockCount = (bytes.length + 7) / 8;  // Round up to handle partial blocks
        long[] blocks = new long[blockCount];

        for (int b = 0; b < blockCount; b++) {
            byte[] blockBytes = new byte[8];
            // Fill with spaces (padding)
            for (int i = 0; i < 8; i++) {
                blockBytes[i] = (byte) ' ';
            }
            // Copy actual bytes for this block
            int start = b * 8;
            int length = Math.min(8, bytes.length - start);
            System.arraycopy(bytes, start, blockBytes, 0, length);

            // Pack into long
            long v = 0L;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (blockBytes[i] & 0xFFL);
            }
            blocks[b] = v;
        }

        return blocks;
    }

    /**
     * Unpack multiple 64-bit blocks back into a string.
     * Trims the result to the original length to remove padding.
     */
    private static String unpackFromBlocks(long[] blocks, int originalLength) {
        StringBuilder sb = new StringBuilder();
        for (long block : blocks) {
            sb.append(unpack8(block));
        }
        // Trim to original length to remove padding
        return sb.substring(0, Math.min(originalLength, sb.length()));
    }

    /**
     * Pack the first 8 bytes of a string into a 64-bit long.
     */
    private static long pack8(String s) {
        byte[] src = s.getBytes(StandardCharsets.UTF_8);
        byte[] eight = new byte[8];

        // Fill with spaces for padding
        for (int i = 0; i < 8; i++) {
            eight[i] = (byte) ' ';
        }
        // Copy actual bytes
        System.arraycopy(src, 0, eight, 0, Math.min(src.length, 8));

        long v = 0L;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (eight[i] & 0xFFL);
        }
        return v;
    }

    /**
     * Unpack a 64-bit long into 8 bytes and build a string.
     */
    private static String unpack8(long v) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    // =========================== Small utilities ============================

    /**
     * Join two 32-bit halves into one 64-bit value.
     */
    private static long join64(int left, int right) {
        return ((long) left << 32) | (right & 0xFFFF_FFFFL);
    }

    /**
     * Format a 64-bit value as a 16-character uppercase hex string.
     */
    private static String toHex64(long v) {
        String s = Long.toHexString(v).toUpperCase();
        return "0".repeat(16 - s.length()) + s;
    }
}
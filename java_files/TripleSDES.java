/*
    Part 2: TripleSDES

    Implementation of Triple SDES (10 bit keys, 8 bit blocks) that computes the ciphertext and recovers the plaintext for a given key/block table
 */

public class TripleSDES {

    // Tables:
    // P10: Permutes the 10 bit key
    private static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    // P8: Picks 8 key bits for a subkey
    private static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    // IP: Initial permutation
    private static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    // IP_INV: Undoes the initial permutation
    private static final int[] IP_INV = {4, 1, 3, 5, 7, 2, 8, 6};
    // EP: Expands the 4bits  to 8 bit
    private static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    // P4: Permutes the S box
    private static final int[] P4 = {2, 4, 3, 1};

    // Each S-Box 0 and 1 maps 4 bits to a value 0-3 (two output bits)
    // Row = outer bits (1'st and 4th), column = inner bits (2nd and 3rd)

    // S0 handles the first 4 bits of the expanded block
    private static final int[][] S0 = {
            {1, 0, 3, 2},
            {3, 2, 1, 0},
            {0, 2, 1, 3},
            {3, 1, 3, 2}
    };

    // S1 Handles the last 4 bits
    private static final int[][] S1 = {
            {0, 1, 2, 3},
            {2, 0, 1, 3},
            {3, 0, 1, 0},
            {2, 1, 0, 3}
    };

    // Permute() applies a permutation/selection table that outputs a bit i, where i is an input bit table[i]
    private static int[] permute(int[] input, int[] table) {
        int[] output = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            output[i] = input[table[i] - 1];
        }
        return output;
    }

    // leftShift(), circular left shift by n positions
    private static int[] leftShift(int[] bits, int n) {
        int[] output = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            output[i] = bits[(i + n) % bits.length];
        }
        return output;
    }

    // xor(), Bitwise xor of two equal length bit arrays
    private static int[] xor(int[] a, int[] b) {
        int[] output = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            output[i] = a[i] ^ b[i];
        }
        return output;
    }

    // concat(): Concatenates two bit arrays end to end
    private static int[] concat(int[] a, int[] b) {
        int[] output = new int[a.length + b.length];
        System.arraycopy(a, 0, output, 0, a.length);
        System.arraycopy(b, 0, output, a.length, b.length);
        return output;
    }

    // slice(): Returns the bits[from, to] as a new array
    private static int[] slice(int[] bits, int from, int to) {
        int[] output = new int[to - from];
        System.arraycopy(bits, from, output, 0, to - from);
        return output;
    }

    // KeySchedule
    /* generateSubkeys(): Derives two 8 bit subkeys from a 10-bit raw key.
        K1 = P8 (LS - 1 (P10(key)))
        K2 = P8 (LS-2 (LS-1(P10(key)))
        in which each ls act separately on the left and right 5-bit halves and return a 2 element array where the index
        0 is K1 and index 1 is K2
    */
    private static int[][] generateSubkeys(int[] key10) {
        int[] permuted = permute(key10, P10);
        int[] left = leftShift(slice(permuted, 0, 5), 1);
        int[] right = leftShift(slice(permuted, 5, 10), 1);
        int[] k1 = permute(concat(left, right), P8);
        left = leftShift(left, 2);
        right = leftShift(right, 2);
        int[] k2 = permute(concat(left, right), P8);
        return new int[][]{k1, k2};
    }


    //Round function

    /*
    f(): Takes the 4 bit right half and an 8 bit subkey, returning 4 bits.
    EP  -> XOR subkey -> S0 and S1 -> P4
     */
    private static int[] f(int[] right4, int[] subkey8) {
        int[] expanded = xor(permute(right4, EP), subkey8);
        // Row index from the outer bits, column index from the inner bits
        int row0 = expanded[0] * 2 + expanded[3];
        int col0 = expanded[1] * 2 + expanded[2];
        int row1 = expanded[4] * 2 + expanded[7];
        int col1 = expanded[5] * 2 + expanded[6];
        int out0 = S0[row0][col0];
        int out1 = S1[row1][col1];
        int[] sboxOutput = {
                (out0 >> 1) & 1, out0 & 1,
                (out1 >> 1) & 1, out1 & 1
        };

        return permute(sboxOutput, P4);
    }

    /* fk(): splits 8 bit blocks into halves, xors F(right, subkey) into the left half and returns that modified left half
    joined to the original right half unchanged
    */
    private static int[] fk(int[] block8, int[] subkey8) {
        int[] left = slice(block8, 0, 4);
        int[] right = slice(block8, 4, 8);
        return concat(xor(left, f(right, subkey8)), right);
    }

    // swap(): Swaps the left and right 4 bit halves
    private static int[] swap(int[] block8) {
        return concat(slice(block8, 4, 8), slice(block8, 0, 4));
    }

    // SINGLE SDES
    /* sdesEncrypt(): encrypts one 8 bit block under a 10 bit key by running the full SDES process:
        - initial permutation
        - f() with K1
        - half swap()
        - second round with K2()
        - inverse permutation
    */
    public static int[] sdesEncrypt(int[] plaintext8, int[] key10) {

        int[][] subkeys = generateSubkeys(key10);
        int[] block = permute(plaintext8, IP);
        block = fk(block, subkeys[0]);
        block = swap(block);
        block = fk(block, subkeys[1]);
        return permute(block, IP_INV);
    }

    // sdesDecrypt(): identical to sdesEncryption, decrypts 8 bit block but subkeys are applied in reverse order (k2 before k1)
    public static int[] sdesDecrypt(int[] ciphertext8, int[] key10) {
        int[][] subkeys = generateSubkeys(key10);
        int[] block = permute(ciphertext8, IP);
        block = fk(block, subkeys[1]);
        block = swap(block);
        block = fk(block, subkeys[0]);
        return permute(block, IP_INV);
    }


    // TRIPLE SDES
    /* tripleEncrypt(): Encrypts one 8 bit block with triple SDES by chaining single SDES three times in the order of
    encrypt, decrypt, encrypt. Uses k1 for the outer two passes and k2 for the middle one
   */
    public static int[] tripleEncrypt(int[] plaintext8, int[] rawKey1, int[] rawKey2) {
        int[] block = sdesEncrypt(plaintext8, rawKey1);
        block = sdesDecrypt(block, rawKey2);
        return sdesEncrypt(block, rawKey1);
    }

    /*
    tripleDecrypt(): Reverses tripleEncrypt() by running the order in reverse: decrypt, encrypt, decrypt with k1 outside and
    k2 in the middle
     */
    public static int[] tripleDecrypt(int[] ciphertext8, int[] rawKey1, int[] rawKey2) {
        int[] block = sdesDecrypt(ciphertext8, rawKey1);
        block = sdesEncrypt(block, rawKey2);
        return sdesDecrypt(block, rawKey1);
    }


    // toBits(): converts a binary string into an int array of 0s and 1's and throws an exception if characters do not contain 0 or 1
    public static int[] toBits(String s) {
        int[] bits = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '0' && c != '1') {
                throw new IllegalArgumentException("Not a binary string: " + s);
            }
            bits[i] = c - '0';
        }
        return bits;
    }

    // toString(): Does the reverse of toBits() in which it joins a bit array back into a printable string of 0 and 1 characters
    public static String toString(int[] bits) {
        StringBuilder sb = new StringBuilder(bits.length);
        for (int bit : bits) {
            sb.append(bit);
        }
        return sb.toString();
    }


    // Main function
    public static void main(String[] args) {

        // 2d Array encrypt rows: for the following first 3 known columns: Raw key 1, Raw key and plaintext. Ciphertext is unknown. Computes the ciphertext
        String[][] encryptRows = {
                {"0000000000", "0000000000", "00000000"},
                {"1000101110", "0110101110", "11010111"},
                {"1000101110", "0110101110", "10101010"},
                {"1111111111", "1111111111", "10101010"}
        };

        // 2d Array for the following last 3 columns: Raw key 1, raw key 2, ciphertext. Plaintext is unknown. Recovers the plaintext
        String[][] decryptRows = {
                {"1000101110", "0110101110", "11100110"},
                {"1011101111", "0110101110", "01010000"},
                {"0000000000", "0000000000", "10000000"},
                {"1111111111", "1111111111", "10010010"}
        };

        // Prints the column headers
        System.out.printf("%-12s  %-12s  %-10s  %-10s%n",
                "Raw Key 1", "Raw Key 2", "Plaintext", "Ciphertext");
        System.out.println("-".repeat(50));

        // goes through each row that gives a plaintext and encrypts it
        for (String[] row : encryptRows) {
            // turns first key string into bits
            int[] k1 = toBits(row[0]);
            // turns the second key string into bits
            int[] k2 = toBits(row[1]);
            // turns the plaintext string into bits
            int[] plaintext = toBits(row[2]);
            // Encrypts both keys then turns the resulting bits back into a string
            String ciphertext = toString(tripleEncrypt(plaintext, k1, k2));
            // prints the row with the ciphertext into the last column
            System.out.printf("%-12s  %-12s  %-10s  %-10s%n",
                    row[0], row[1], row[2], ciphertext);
        }
        // goes through each row that gives us a ciphertext and works backwards to the plaintext
        for (String[] row : decryptRows) {
            // turns the first key string into bits
            int[] k1 = toBits(row[0]);
            // turns the second key string into bits
            int[] k2 = toBits(row[1]);
            // turns the ciphertext string into bits
            int[] ciphertext = toBits(row[2]);
            // decrypts with both keys and then turns the resulting bits into a string
            String plaintext = toString(tripleDecrypt(ciphertext, k1, k2));
            // prints the row with the plaintext into the third column
            System.out.printf("%-12s  %-12s  %-10s  %-10s%n",
                    row[0], row[1], plaintext, row[2]);
        }
    }
}
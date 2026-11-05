
import java.util.Arrays;

public class SDES {

    // standard sdes permutation tables
    static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    static final int[] IP_INV = {4, 1, 3, 5, 7, 2, 8, 6};
    static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    static final int[] P4 = {2, 4, 3, 1};

    // standard sdes s-boxes
    static final int[][] S0 = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}
    };

    static final int[][] S1 = {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}
    };

    // rearrange bits according to a permutation table
    static byte[] permute(byte[] bits, int[] order) {
        byte[] result = new byte[order.length];

        for (int i = 0; i < order.length; i++) {
            result[i] = bits[order[i] - 1];
        }

        return result;
    }

    // circular left shift
    static byte[] leftShift(byte[] bits, int count) {
        byte[] result = new byte[bits.length];

        for (int i = 0; i < bits.length; i++) {
            result[i] = bits[(i + count) % bits.length];
        }

        return result;
    }

    // combine two byte arrays
    static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // xor two byte arrays
    static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];

        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }

        return result;
    }

    // generate subkeys k1 and k2 from the 10-bit raw key
    static byte[][] generateKeys(byte[] rawkey) {
        byte[] p10 = permute(rawkey, P10);

        byte[] left = Arrays.copyOfRange(p10, 0, 5);
        byte[] right = Arrays.copyOfRange(p10, 5, 10);

        // shift both halves left by 1
        left = leftShift(left, 1);
        right = leftShift(right, 1);

        byte[] k1 = permute(concat(left, right), P8);

        // shift both halves left by 2 more positions
        left = leftShift(left, 2);
        right = leftShift(right, 2);

        byte[] k2 = permute(concat(left, right), P8);

        return new byte[][] {k1, k2};
    }

    // s-box substitution: 4 bits become 2 bits
    static byte[] sbox(byte[] bits, int[][] box) {
        int row = bits[0] * 2 + bits[3];
        int col = bits[1] * 2 + bits[2];

        int value = box[row][col];

        return new byte[] {
            (byte) (value / 2),
            (byte) (value % 2)
        };
    }

    // feistel function
    static byte[] fk(byte[] bits, byte[] key) {
        byte[] left = Arrays.copyOfRange(bits, 0, 4);
        byte[] right = Arrays.copyOfRange(bits, 4, 8);

        // expand right half and xor with subkey
        byte[] expanded = permute(right, EP);
        byte[] x = xor(expanded, key);

        // apply s-boxes
        byte[] s0 = sbox(Arrays.copyOfRange(x, 0, 4), S0);
        byte[] s1 = sbox(Arrays.copyOfRange(x, 4, 8), S1);

        // apply p4 and xor with left half
        byte[] p4 = permute(concat(s0, s1), P4);
        byte[] newLeft = xor(left, p4);

        return concat(newLeft, right);
    }

    // swap left and right halves
    static byte[] swap(byte[] bits) {
        byte[] left = Arrays.copyOfRange(bits, 0, 4);
        byte[] right = Arrays.copyOfRange(bits, 4, 8);

        return concat(right, left);
    }

    // encrypt 8-bit plaintext using a 10-bit raw key
    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        byte[][] keys = generateKeys(rawkey);

        byte[] bits = permute(plaintext, IP);
        bits = fk(bits, keys[0]);
        bits = swap(bits);
        bits = fk(bits, keys[1]);
        bits = permute(bits, IP_INV);

        return bits;
    }

    // decrypt 8-bit ciphertext using a 10-bit raw key
    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
        byte[][] keys = generateKeys(rawkey);

        byte[] bits = permute(ciphertext, IP);
        bits = fk(bits, keys[1]);
        bits = swap(bits);
        bits = fk(bits, keys[0]);
        bits = permute(bits, IP_INV);

        return bits;
    }

    // convert a binary string into a byte array
    static byte[] toBytes(String binary) {
        byte[] result = new byte[binary.length()];

        for (int i = 0; i < binary.length(); i++) {
            result[i] = (byte) (binary.charAt(i) - '0');
        }

        return result;
    }

    // convert byte array into a binary string
    static String toBinary(byte[] bits) {
        StringBuilder result = new StringBuilder();

        for (byte bit : bits) {
            result.append(bit);
        }

        return result.toString();
    }

    public static void main(String[] args) {

        System.out.println("SDES Encryption Test Cases:");

        String[][] tests = {
            {"0000000000", "10101010", "00010001"},
            {"1110001110", "10101010", "11001010"},
            {"1110001110", "01010101", "01110000"},
            {"1111111111", "10101010", "00000100"}
        };

        for (String[] test : tests) {
            byte[] key = toBytes(test[0]);
            byte[] plaintext = toBytes(test[1]);

            byte[] ciphertext = Encrypt(key, plaintext);

            System.out.println(
                "Key: " + test[0] +
                " Plaintext: " + test[1] +
                " Ciphertext: " + toBinary(ciphertext) +
                " Expected: " + test[2] +
                " Passed: " + toBinary(ciphertext).equals(test[2])
            );
        }

        System.out.println("\nTable:");

        String[][] encryptionCases = {
            {"0000000000", "00000000"},
            {"1111111111", "11111111"},
            {"0000011111", "00000000"},
            {"0000011111", "11111111"}
        };

        for (String[] test : encryptionCases) {
            byte[] result = Encrypt(
                toBytes(test[0]), toBytes(test[1])
            );

            System.out.println(
                test[0] + " " + test[1] + " " + toBinary(result)
            );
        }

        String[][] decryptionCases = {
            {"1000101110", "00011100"},
            {"1000101110", "11000010"},
            {"0010011111", "10011101"},
            {"0010011111", "10010000"}
        };

        for (String[] test : decryptionCases) {
            byte[] result = Decrypt(
                toBytes(test[0]), toBytes(test[1])
            );

            System.out.println(
                test[0] + " " + toBinary(result) + " " + test[1]
            );
        }
    }
}

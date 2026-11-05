// part 1: sdes
import java.util.Arrays;

// this class implements the simplified data encryption standard.
class SDES{
    // fixed permutation tables used by the sdes key schedule.
    static int[] P10 = {3,5,2,7,4,10,1,9,8,6};
    static int[] P8 = {6,3,7,4,8,5,10,9};
    static int[] IP = {2,6,3,1,4,8,5,7};
    static int[] IP_INV = {4,1,3,5,7,2,8,6};
    static int[] EP = {4,1,2,3,2,3,4,1};
    static int[] P4 = {2,4,3,1};
    static int[][] S0 = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
    static int[][] S1 = {{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};

    // apply a permutation to a bit string using the given order list.
    static String permute(String s, int[] order) {
        String result = "";
        for (int i : order) result += s.charAt(i - 1);
        return result;
    }

    // rotate the leftmost part of the bit string by n positions.
    static String shift(String s, int n) {
        return s.substring(n) + s.substring(0, n);
    }

    // xor two equal-length bit strings.
    static String xor(String a, String b) {
        String result = "";
        for (int i = 0; i < a.length(); i++)
            result += a.charAt(i) == b.charAt(i) ? "0" : "1";
        return result;
    }

    // generate the two subkeys for the sdes rounds.
    static String[] keys(String key) {
        String p = permute(key, P10);
        String left = shift(p.substring(0, 5), 1);
        String right = shift(p.substring(5), 1);
        String k1 = permute(left + right, P8);
        left = shift(left, 2);
        right = shift(right, 2);
        return new String[]{k1, permute(left + right, P8)};
    }

    // lookup a value from the s-box using the given input bits.
    static String sbox(String bits, int[][] box) {
        int row = Integer.parseInt("" + bits.charAt(0) + bits.charAt(3), 2);
        int col = Integer.parseInt(bits.substring(1, 3), 2);
        return String.format("%2s", Integer.toBinaryString(box[row][col])).replace(' ', '0');
    }

    // run a single feistel round on the input block.
    static String round(String bits, String key) {
        String left = bits.substring(0, 4);
        String right = bits.substring(4);
        String x = xor(permute(right, EP), key);
        String s = sbox(x.substring(0, 4), S0) + sbox(x.substring(4), S1);
        return xor(left, permute(s, P4)) + right;
    }

    // apply the full encryption or decryption flow for sdes.
    static String run(String bits, String first, String second) {
        bits = round(permute(bits, IP), first);
        bits = bits.substring(4) + bits.substring(0, 4);
        return permute(round(bits, second), IP_INV);
    }

    // encrypt a plaintext block with the provided key.
    public static String encrypt(String plaintext, String key) {
        String[] k = keys(key);
        return run(plaintext, k[0], k[1]);
    }

    // decrypt a ciphertext block with the provided key.
    public static String decrypt(String ciphertext, String key) {
        String[] k = keys(key);
        return run(ciphertext, k[1], k[0]);
    }

    // print a formatted table of key, plaintext, and ciphertext results.
    static void printTable(String[][] rows) {
        int keyWidth = 10;
        int ptWidth = 10;
        int ctWidth = 10;

        for (String[] row : rows) {
            keyWidth = Math.max(keyWidth, row[0].length());
            ptWidth = Math.max(ptWidth, row[1].length());
            ctWidth = Math.max(ctWidth, row[2].length());
        }

        String format = "| %-" + keyWidth + "s | %-" + ptWidth + "s | %-" + ctWidth + "s |%n";
        System.out.printf(format, "Raw Key", "Plaintext", "Ciphertext");
        System.out.printf("|-%s-|-%s-|-%s-|%n", "-".repeat(keyWidth), "-".repeat(ptWidth), "-".repeat(ctWidth));

        for (String[] row : rows) {
            System.out.printf(format, row[0], row[1], row[2]);
        }
    }

    // run a small set of known test vectors for encryption.
    public static void main(String[] args) {
        String[][] tests = {
            {"0000000000", "10101010", "00010001"},
            {"1110001110", "10101010", "11001010"},
            {"1110001110", "01010101", "01110000"},
            {"1111111111", "10101010", "00000100"}
        };
        for (String[] test : tests) {
            String result = encrypt(test[1], test[0]);
            System.out.println(result + " " + (result.equals(test[2]) ? "PASS" : "FAIL"));
        }

        // show a table of decrypt and encrypt values for validation.
        String[][] table = {
            {"0000000000", "00000000", encrypt("00000000", "0000000000")},
            {"1111111111", "11111111", encrypt("11111111", "1111111111")},
            {"0000011111", "00000000", encrypt("00000000", "0000011111")},
            {"0000011111", "11111111", encrypt("11111111", "0000011111")},
            {"1000101110", decrypt("00011100", "1000101110"), "00011100"},
            {"1000101110", decrypt("11000010", "1000101110"), "11000010"},
            {"0010011111", decrypt("10011101", "0010011111"), "10011101"},
            {"0010011111", decrypt("10010000", "0010011111"), "10010000"}
        };

        System.out.println();
        printTable(table);
    }
}

/*
    Part 3: Cracking TripleSDES
 */



// Importing libraries
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class CrackingTripleSDES {

    // CascII alphabet from 0 = ’ ’ (space), 1–26 = ’A’–’Z’, 27=’,’, 28 = ’?’, 29=’:’, 30=’.’, 31 = ’‘’.
    private static final String alphabet = " ABCDEFGHIJKLMNOPQRSTUVWXYZ,?:.'";

    // Default message file, looks for msg2.txt in the current directory
    private static final String DEFAULT_FILE = "msg2.txt";

    // Per-key lookup tables: encrypt[k][b] is the S-DES encryption of byte b under key k.
    private static final int[][] encrypt = new int[1024][256];
    private static final int[][] decrypt = new int[1024][256];

    // buildTables(): runs SDES on all 256 possible bytes under all 1024 possible keys once, up front.
    private static void buildTables() {
        for (int k = 0; k < 1024; k++) {
            int[] keyBits = toBits(k, 10);
            for (int b = 0; b < 256; b++) {
                int[] block = toBits(b, 8);
                encrypt[k][b] = toInt(TripleSDES.sdesEncrypt(block, keyBits));
                decrypt[k][b] = toInt(TripleSDES.sdesDecrypt(block, keyBits));
            }
        }
    }

    // toBits(): splits a number into an array of 0s and 1s of the width that is being asked for, since TripleSDES works on bit arrays.
    private static int[] toBits(int value, int width) {
        int[] bits = new int[width];
        for (int i = 0; i < width; i++) {
            bits[i] = (value >> (width - 1 - i)) & 1;
        }
        return bits;
    }

    // toInt(): converts a bit array back into an integer
    private static int toInt(int[] bits) {
        int value = 0;
        for (int bit : bits) {
            value = (value << 1) | bit;
        }
        return value;
    }

    // decodeCascII(): turns the decrypted bytes back into readable text. It strings all the bits together and takes them 5 at a time and looks at each group up in the alphabet. Each group is read smallest bit first. Leftover bits at the end are padding zeros and are ignored.
    private static String decodeCascII(int[] bytes) {
        StringBuilder bits = new StringBuilder(bytes.length * 8);
        for (int b : bytes) {
            for (int i = 7; i >= 0; i--) {
                bits.append((b >> i) & 1);
            }
        }
        StringBuilder text = new StringBuilder(bits.length() / 5);
        for (int i = 0; i + 5 <= bits.length(); i += 5) {
            int value = 0;
            for (int j = 0; j < 5; j++) {
                value |= (bits.charAt(i + j) - '0') << j;   // LSB first
            }
            text.append(alphabet.charAt(value));
        }
        return text.toString();
    }



    // Score(): rates how much a decrypted text looks like english, so the search can pick the real plaintext out of a million pieces of random characters.

    private static int score(String text) {
        // count for number of spaces and punctuation
        int spaces = 0;
        int punctuation = 0;
        // count the spaces
        for (char c : text.toCharArray()) {
            if (c == ' ') {
                spaces++;
            }
            // Counts the punctuation
            else if (!Character.isLetter(c)) {
                punctuation++;
            }
        }
        // sentences have plenty of spaces and hardly any punctuation, so it rejects anything outside those bounds with the worst score possible
        if (spaces < 8 || punctuation > 4) return Integer.MIN_VALUE;

        // Whatever survives gets judged word by word
        int points = 0;
        for (String word : text.split(" ")) {
            // drops any trailing punctuation
            String stripped = word.replaceAll("[^A-Z]", "");
            // skip double spaces
            if (stripped.isEmpty()){
                continue;
            }
            // Almost every English word has a vowel
            boolean hasVowel = stripped.matches(".*[AEIOU].*");
            points += (hasVowel && stripped.length() <= 12) ? 2 : -2;
        }
        return points;
    }




    // locate(): finds the msg2.txt file and if it is unable to find it will throw an exception error.
    private static Path locate(String name) throws IOException {
        Path direct = Path.of(name);
        if (Files.exists(direct)) return direct;
        Path nested = Path.of("java_files", name);
        if (Files.exists(nested)) return nested;
        throw new IOException("Could not find " + name + ". Looked in "
                + direct.toAbsolutePath() + " and " + nested.toAbsolutePath());
    }


    // Main
    public static void main(String[] args) throws IOException {


        // Reads the encrypted message from msg2.txt or a different file
        Path file = locate(args.length > 0 ? args[0] : DEFAULT_FILE);
        // Reads the whole file and throws away anything unrelated that isn't a 0 or 1
        String cipherBits = Files.readString(file).replaceAll("[^01]", "");


        // Split the message into 8-bit blocks.
        int[] blocks = new int[cipherBits.length() / 8];
        for (int i = 0; i < blocks.length; i++) {
            // Takes the next 8 characters and reads them as a binary number
            blocks[i] = Integer.parseInt(cipherBits.substring(i * 8, i * 8 + 8), 2);
        }

        System.out.println("Message: " + cipherBits.length() + " bits, "
                + blocks.length + " blocks, " + (cipherBits.length() / 5) + " CASCII characters");
        System.out.println("Searching all 1048576 key pairs...\n");

        // Fills in the encrypt/decrypt answer sheets before the search starts
        buildTables();

        // Remembers the best score found so far and starts with a score nothing can lose to
        int bestScore = Integer.MIN_VALUE, bestK1 = -1, bestK2 = -1;
        String bestText = "";

        // temporary space for the current decryption, reused every time instead of reallocating space
        int[] candidate = new int[blocks.length];

        // Tries every possible key
        for (int k1 = 0; k1 < 1024; k1++) {
            // D(k1, c) depends only on k1, so compute it once per outer key.
            int[] firstPass = new int[blocks.length];
            for (int i = 0; i < blocks.length; i++) {
                // Decrypts each block with k1
                firstPass[i] = decrypt[k1][blocks[i]];
            }
            // Tries every possible second key against the first key
            for (int k2 = 0; k2 < 1024; k2++) {
                for (int i = 0; i < blocks.length; i++) {
                    // Finishes the other two steps of: encrypting with k2 and then decrypting with k1 again
                    candidate[i] = decrypt[k1][encrypt[k2][firstPass[i]]];
                }
                // Turns the decrypted bytes into readable text
                String text = decodeCascII(candidate);
                // Rate how much that text looks like english.
                int s = score(text);
                // If it beats everything so far, save it and the keys that produced it
                if (s > bestScore) {
                    bestScore = s;
                    bestK1 = k1;
                    bestK2 = k2;
                    bestText = text;
                }
            }
        }

        // Prints the raw key
        System.out.printf("Raw Key 1: %10s%n", Integer.toBinaryString(bestK1 | 1024).substring(1));
        System.out.printf("Raw Key 2: %10s%n", Integer.toBinaryString(bestK2 | 1024).substring(1));
        System.out.println();
        // Prints the decrypted message from the encoded tripleSDES message from the msg2.txt
        System.out.println("Decrypted message:");
        System.out.println(bestText);
    }
}

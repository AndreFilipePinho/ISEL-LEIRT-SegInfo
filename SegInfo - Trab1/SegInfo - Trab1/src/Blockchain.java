import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;


public class Blockchain{

    // new block hash must be bellow 1024
    private static final int TARGET = 1024;

    private static final Path directoryPath = Paths.get("SegInfo - Trab1/src/Blocks");

    private static final List<Double> blockCreationTimeList = new ArrayList<>();


    // Calculates SHA-256 and keeps the first 16 bits
    private static byte[] hash16(byte[] message) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(message);

        // First 16 bits = first 2 bytes
        return new byte[] { digest[0], digest[1] };

    }


    // Converts a hash 2-byte value to an unsigned integer
    private static int hash16ToInt(byte[] hash) {

        return ((hash[0] & 0xff) << 8) | (hash[1] & 0xff);
    }


    // Concatenates three byte arrays
    private static byte[] concatenate( byte[] a, byte[] b, byte[] c) {

        byte[] result = new byte[ a.length + b.length + c.length ];
        System.arraycopy( a, 0, result, 0, a.length );
        System.arraycopy( b, 0, result, a.length, b.length );
        System.arraycopy( c, 0, result, a.length + b.length, c.length );

        return result;
    }


    // Finds the index of the next block
    public static int getNextBlockIndex() throws IOException {

        int index = 0;
        while (Files.exists(
                Paths.get(directoryPath + "/" + index + ".txt"))) {

            index++;
        }

        return index;
    }


    // Reads the hash of the previous block
    private static byte[] getPreviousHash(int index) throws IOException {

        if (index == 0) {   // If there is no previous block, previous hash = 0
            return new byte[] { 0, 0 };
        }
        Path previousHash = Paths.get(directoryPath + "/" + (index - 1) + ".hsh");

        return Files.readAllBytes(previousHash);
    }


    public static int getBlockNonce(int index) throws IOException {
        Path noncePath = Paths.get(directoryPath + "/" + (index) + ".nce");
        return Integer.parseInt(Files.readString(noncePath));
    }


    public static double getBlockCreationTime(int index) {
        return blockCreationTimeList.get(index);
    }


    // Creates a new block
    private static void createBlock(String data) throws Exception {

        if(Files.notExists(directoryPath)){ Files.createDirectory(directoryPath); }


        int index = getNextBlockIndex();
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] previousHash = getPreviousHash(index);

        long nonce = 0;
        long attempts = 0;
        byte[] currentHash;

        long startTime = System.nanoTime();
        while (true) {
            byte[] nonceBytes = Long.toString(nonce).getBytes(StandardCharsets.UTF_8);

            // H16 = SHA256(data || nonce || previousHash)
            byte[] message = concatenate( dataBytes, nonceBytes, previousHash );

            currentHash = hash16(message);
            attempts++;

            int hashValue = hash16ToInt(currentHash);
            if (hashValue < TARGET) {
                break;
            }

            nonce++;
        }

        long endTime = System.nanoTime();
        double elapsedSeconds = (endTime - startTime) / 1_000_000_000.0;
        blockCreationTimeList.add(elapsedSeconds);

        // Write block files.
        Files.write(
                Paths.get(directoryPath + "/" + index + ".txt"),
                dataBytes
        );

        Files.writeString(
                Paths.get(directoryPath + "/" + index + ".nce"),
                Long.toString(nonce),
                StandardCharsets.UTF_8
        );

        Files.write(
                Paths.get(directoryPath + "/" + index + ".hsh"),
                currentHash
        );

        System.out.println("\n----------------------------------------------------------------");
        System.out.println( "Block: " + index );
        System.out.println( "Nonce: " + nonce );
        System.out.println( "Attempts: " + attempts );
        System.out.println( "Hash value: " + hash16ToInt(currentHash) );
        System.out.println( String.format( "Time: %.6f seconds", elapsedSeconds ) );
        System.out.println("----------------------------------------------------------------");

    }


    public static void main(String[] args) throws Exception {

        Path path = Paths.get("SegInfo - Trab1/src/alice.txt");

        int nBlocks = 1;
        if(args.length == 1){
            nBlocks = Integer.parseInt(args[0]);
        }

        // if there is a argument it needs to be superior or equal to 0
        if (args.length > 1 || nBlocks < 1) {
            System.err.println( "Insert how many blocks/lines will be created/read! \nex: 100" );
            System.exit(1);
        }

        if(!Files.exists(path)) {
            System.err.println("Current working directory: " + Paths.get("").toAbsolutePath());
            System.err.println("File does not exist");
            System.exit(1);
        }

        List<String> textLines = Files.readAllLines(path);
        SecureRandom secureRand = new SecureRandom();

        int min = 0;
        int max = textLines.size() - 1;

        for (int i = 0; i < nBlocks; i++) {
            int randomInInterval = secureRand.nextInt((max - min) + 1) + min;
            createBlock(textLines.get(randomInInterval));
        }
        System.out.println("\nALL DONE!\n");

        // nBlocks now represents the number of existing blocks, not the number of blocks to create
        nBlocks = getNextBlockIndex();

        // calculating the mean
        int nonceSum = 0;
        double blockCreationTimeSum = 0;
        for (int i = 0; i < nBlocks; i++) {
            nonceSum += getBlockNonce(i);
            blockCreationTimeSum += getBlockCreationTime(i);
        }

        System.out.println("Average nonce: " +  nonceSum / nBlocks);
        System.out.println("Average blockCreationTime: " +  blockCreationTimeSum / nBlocks);

        System.exit(0);
    }


}




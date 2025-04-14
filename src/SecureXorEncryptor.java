import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecureXorEncryptor {
    private static final int SALT_SIZE = 16;
    private static final int KEY_ITERATIONS = 10000;
    private static final int HASH_SIZE = 32;
    public static void main(String[] args) {
        try {
            if (args.length < 3 || "-h".equals(args[0]) || "--help".equals(args[0])) {
                displayHelp();
                return;
            }

            int argIndex = 0;
            boolean isEncrypting = true;

            if ("-e".equals(args[argIndex])) {
                isEncrypting = true;
                argIndex++;
            } else if ("-d".equals(args[argIndex])) {
                isEncrypting = false;
                argIndex++;
            }

            if (args.length - argIndex < 3) {
                System.err.println("Error: Insufficient arguments");
                displayHelp();
                System.exit(1);
            }

            String inputFile = args[argIndex++];
            String outputFile = args[argIndex++];
            String keyFile = args[argIndex++];

            System.out.println("Mode: " + (isEncrypting ? "Encryption" : "Decryption"));
            System.out.println("Input file: " + inputFile);
            System.out.println("Output file: " + outputFile);
            System.out.println("Key file: " + keyFile);

            boolean success = processFile(inputFile, outputFile, keyFile, isEncrypting);
            System.exit(success ? 0 : 1);
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void displayHelp() {
        System.out.println("Secure XOR File Encryptor/Decryptor");
        System.out.println("Usage: java SecureXorEncryptor [options] <input_file> <output_file> <key_file>");
        System.out.println("Options:");
        System.out.println("  -e            Encrypt mode (default)");
        System.out.println("  -d            Decrypt mode");
        System.out.println("  -h, --help    Display this help message");
    }

    private static boolean processFile(String inputFilePath, String outputFilePath, String keyFilePath,
            boolean isEncrypting) {
        FileInputStream inStream = null;
        FileOutputStream outStream = null;

        try {
            File inputFile = new File(inputFilePath);
            if (!inputFile.exists() || !inputFile.isFile()) {
                System.err.println("Error: Input file does not exist: " + inputFilePath);
                return false;
            }

            File keyFile = new File(keyFilePath);
            if (!keyFile.exists() || !keyFile.isFile()) {
                System.err.println("Error: Key file does not exist: " + keyFilePath);
                return false;
            }

            byte[] key = readKeyFile(keyFilePath);
            if (key == null || key.length == 0) {
                System.err.println("Error: Invalid key file");
                return false;
            }

            System.out.println("Authentication required for " + (isEncrypting ? "encryption" : "decryption"));
            if (!authenticateUser()) {
                System.err.println("Authentication failed. Aborting operation.");
                return false;
            }

            inStream = new FileInputStream(inputFile);
            byte[] salt;
            byte[] fileHash;
            byte[] fileData;

            if (isEncrypting) {
                salt = generateSalt();
                fileData = new byte[(int) inputFile.length()];
                inStream.read(fileData);
                fileHash = calculateHash(fileData);
            } else {
                long fileSize = inputFile.length();
                if (fileSize < SALT_SIZE + HASH_SIZE) {
                    System.err.println("Error: Input file is too small to be a valid encrypted file");
                    return false;
                }

                salt = new byte[SALT_SIZE];
                inStream.read(salt);
                fileHash = new byte[HASH_SIZE];
                inStream.read(fileHash);
                int encryptedDataSize = (int) (fileSize - SALT_SIZE - HASH_SIZE);
                fileData = new byte[encryptedDataSize];
                inStream.read(fileData);
            }

            inStream.close();
            inStream = null;

            Scanner scanner = new Scanner(System.in);
            char[] passwordChars;

            if (System.console() != null) {
                System.out.println("Enter encryption/decryption password: ");
                passwordChars = scanner.nextLine().toCharArray();
            } else {
                System.out.print("Enter encryption/decryption password: ");
                passwordChars = scanner.nextLine().toCharArray();
            }

            byte[] derivedKey = deriveKeyFromPassword(passwordChars, salt);
            Arrays.fill(passwordChars, '\0');

            byte[] combinedKey = new byte[key.length];
            for (int i = 0; i < key.length; i++) {
                combinedKey[i] = (byte) (key[i] ^ derivedKey[i % derivedKey.length]);
            }

            Arrays.fill(key, (byte) 0);

            int numThreads = Runtime.getRuntime().availableProcessors();
            if (numThreads < 1)
                numThreads = 4;

            processDataWithThreads(fileData, combinedKey, numThreads);

            if (!isEncrypting) {
                byte[] calculatedHash = calculateHash(fileData);
                if (!Arrays.equals(calculatedHash, fileHash)) {
                    System.err.println(
                            "Error: Data integrity check failed. The file may be corrupted or the wrong key was used.");
                    return false;
                }
            }

            outStream = new FileOutputStream(outputFilePath);
            if (isEncrypting) {
                outStream.write(salt);
                outStream.write(fileHash);
            }

            outStream.write(fileData);
            outStream.close();
            outStream = null;

            Arrays.fill(derivedKey, (byte) 0);
            Arrays.fill(combinedKey, (byte) 0);

            System.out.println("File " + (isEncrypting ? "encrypted" : "decrypted") + " successfully.");
            return true;
        } catch (IOException e) {
            System.err.println("I/O Error: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.err.println("Error during processing: " + e.getMessage());
            e.printStackTrace();
            return false;
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                }
            }
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private static void processDataWithThreads(byte[] data, byte[] key, int numThreads) throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);

        int chunkSize = data.length / numThreads;

        for (int i = 0; i < numThreads; i++) {
            final int startPos = i * chunkSize;
            final int endPos = (i == numThreads - 1) ? data.length : (i + 1) * chunkSize;

            executor.submit(() -> {
                try {
                    processDataChunk(data, key, startPos, endPos);
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await();
        executor.shutdown();
    }

    private static void processDataChunk(byte[] data, byte[] key, int startPos, int endPos) {
        final int keySize = key.length;

        for (int i = startPos; i < endPos && i < data.length; ++i) {
            data[i] ^= key[i % keySize];
        }
    }

    private static byte[] readKeyFile(String keyFilePath) {
        FileInputStream keyStream = null;
        try {
            File keyFile = new File(keyFilePath);
            keyStream = new FileInputStream(keyFile);
            byte[] key = new byte[(int) keyFile.length()];
            keyStream.read(key);

            if (key.length == 0) {
                throw new IOException("Key file is empty");
            }

            return key;
        } catch (IOException e) {
            System.err.println("Error reading key file: " + e.getMessage());
            return null;
        } finally {
            if (keyStream != null) {
                try {
                    keyStream.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(salt);
        } catch (NoSuchAlgorithmException e) {
            new Random().nextBytes(salt);
            System.err.println("Warning: Using less secure random source for salt generation");
        }
        return salt;
    }

    private static byte[] deriveKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, KEY_ITERATIONS, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    private static byte[] calculateHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Integrity check error: SHA-256 not available");
            return new byte[HASH_SIZE];
        }
    }

    private static boolean authenticateUser() {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter authentication password: ");
        String password = scanner.nextLine();

        System.out.print("Confirm password: ");
        String confirmPassword = scanner.nextLine();

        boolean isAuthenticated = password.equals(confirmPassword);

        return isAuthenticated;
    }
}
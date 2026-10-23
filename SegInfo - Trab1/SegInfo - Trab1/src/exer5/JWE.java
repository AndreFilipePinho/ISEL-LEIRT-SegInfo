package exer5;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class JWE {
    private JWE() {}

    // Convenience for this assignment only; don't hardcode real passwords in production.
    private static final char[] DEFAULT_PRIVATE_KEY_PASSWORD = "changeit".toCharArray();

    private static final String KEY_ALGORITHM = "RSA-OAEP-256";
    private static final String CONTENT_ALGORITHM = "A256GCM";
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final String DEFAULT_TOKEN_FILE = "jwe-token.txt";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    static final class GCMResult {
        final byte[] ciphertext;
        final byte[] tag;
        GCMResult(byte[] ciphertext, byte[] tag) {
            this.ciphertext = ciphertext;
            this.tag = tag;
        }
    }

    // (a) AES-GCM; JCA returns ciphertext followed by the authentication tag.
    static GCMResult aesEncrypt(String plaintext, byte[] aad, SecretKey key, byte[] iv)
            throws GeneralSecurityException {
        checkIv(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        byte[] combined = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        int ciphertextLength = combined.length - TAG_LENGTH_BYTES;
        return new GCMResult(Arrays.copyOfRange(combined, 0, ciphertextLength),
                Arrays.copyOfRange(combined, ciphertextLength, combined.length));
    }

    static String aesDecrypt(byte[] ciphertext, byte[] tag, byte[] aad,
                             SecretKey key, byte[] iv) throws GeneralSecurityException {
        checkIv(iv);
        if (tag.length != TAG_LENGTH_BYTES) throw new IllegalArgumentException("Invalid GCM tag length.");
        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return new String(cipher.doFinal(combined), StandardCharsets.UTF_8);
    }

    private static void checkIv(byte[] iv) {
        if (iv == null || iv.length != IV_LENGTH_BYTES)
            throw new IllegalArgumentException("AES-GCM IV must be 12 bytes.");
    }

    // (b) RSA-OAEP-256 wraps the AES key.
    static byte[] rsaEncryptKey(SecretKey aesKey, PublicKey publicKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_PARAMS);
        return cipher.doFinal(aesKey.getEncoded());
    }

    static SecretKey rsaDecryptKey(byte[] encryptedKey, PrivateKey privateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_PARAMS);
        byte[] rawKey = cipher.doFinal(encryptedKey);
        if (rawKey.length != AES_KEY_SIZE / 8)
            throw new GeneralSecurityException("Recovered AES key has invalid length.");
        return new SecretKeySpec(rawKey, "AES");
    }

    // (c) Load X.509 certificate and check its validity dates.
    static X509Certificate loadCertificate(String filename) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(Path.of(filename))) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            cert.checkValidity();
            if (!"RSA".equalsIgnoreCase(cert.getPublicKey().getAlgorithm()))
                throw new GeneralSecurityException("Certificate does not contain an RSA public key.");
            return cert;
        }
    }

    static PrivateKey loadPrivateKey(String filename, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(filename))) {
            store.load(in, password);
        }
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!store.isKeyEntry(alias)) continue;
            Key key = store.getKey(alias, password);
            if (!(key instanceof PrivateKey)) continue;
            PrivateKey privateKey = (PrivateKey) key;
            if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) continue;
            Certificate cert = store.getCertificate(alias);
            if (cert instanceof X509Certificate) ((X509Certificate) cert).checkValidity();
            return privateKey;
        }
        throw new GeneralSecurityException("No RSA private key found in the PKCS#12 keystore.");
    }

    // (d) JWE Compact Serialization: protected.encryptedKey.iv.ciphertext.tag
    static String encrypt(String plaintext, String certificateFile) throws Exception {
        PublicKey publicKey = loadCertificate(certificateFile).getPublicKey();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_SIZE, RANDOM);
        SecretKey aesKey = generator.generateKey();

        byte[] encryptedKey = rsaEncryptKey(aesKey, publicKey);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        String header = "{\"alg\":\"" + KEY_ALGORITHM + "\",\"enc\":\"" + CONTENT_ALGORITHM + "\"}";
        String encodedHeader = B64URL.encodeToString(header.getBytes(StandardCharsets.UTF_8));
        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
        GCMResult result = aesEncrypt(plaintext, aad, aesKey, iv);

        return encodedHeader + "."
                + B64URL.encodeToString(encryptedKey) + "."
                + B64URL.encodeToString(iv) + "."
                + B64URL.encodeToString(result.ciphertext) + "."
                + B64URL.encodeToString(result.tag);
    }

    static String decrypt(String token, String pfxFile, char[] password) throws Exception {
        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 5)
            throw new IllegalArgumentException("Invalid JWE: expected five dot-separated parts.");

        String encodedHeader = parts[0];
        String header = new String(B64URL_DEC.decode(encodedHeader), StandardCharsets.UTF_8);
        if (!header.matches("\\s*\\{\\s*\"alg\"\\s*:\\s*\"RSA-OAEP-256\"\\s*,"
                + "\\s*\"enc\"\\s*:\\s*\"A256GCM\"\\s*}\\s*"))
            throw new IllegalArgumentException("Unsupported JWE algorithms/header.");

        byte[] encryptedKey = B64URL_DEC.decode(parts[1]);
        byte[] iv = B64URL_DEC.decode(parts[2]);
        byte[] ciphertext = B64URL_DEC.decode(parts[3]);
        byte[] tag = B64URL_DEC.decode(parts[4]);
        checkIv(iv);
        if (tag.length != TAG_LENGTH_BYTES)
            throw new IllegalArgumentException("Invalid JWE authentication tag.");

        PrivateKey privateKey = loadPrivateKey(pfxFile, password);
        SecretKey aesKey = rsaDecryptKey(encryptedKey, privateKey);
        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
        return aesDecrypt(ciphertext, tag, aad, aesKey, iv);
    }

    private static char[] getPassword() {
        // Environment variable overrides the assignment default if provided.
        String env = System.getenv("JWE_PFX_PASSWORD");
        return env == null ? DEFAULT_PRIVATE_KEY_PASSWORD.clone() : env.toCharArray();
    }

    private static String readToken(String argument) throws Exception {
        // @file always means file; an existing path is also read as a file.
        boolean forceFile = argument.startsWith("@");
        String filename = forceFile ? argument.substring(1) : argument;
        Path path = Path.of(filename);
        if (forceFile || Files.isRegularFile(path))
            return Files.readString(path, StandardCharsets.UTF_8).trim();
        return argument.trim(); // Also accept a literal JWE token.
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java -cp src exer5.JWE enc \"text\" <certificate.cer> [token-file]");
        System.err.println("  java -cp src exer5.JWE dec <token-file-or-token> <recipient.pfx>");
        System.err.println("Encryption saves to " + DEFAULT_TOKEN_FILE + " by default.");
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            usage();
            System.exit(2);
        }
        try {
            if ("enc".equalsIgnoreCase(args[0])) {
                if (args.length < 3 || args.length > 4) {
                    usage();
                    System.exit(2);
                }
                String token = encrypt(args[1], args[2]);
                Path output = Path.of(args.length == 4 ? args[3] : DEFAULT_TOKEN_FILE);
                Files.writeString(output, token + System.lineSeparator(), StandardCharsets.UTF_8);
                System.out.println("\nJWE token = " + token);
                System.out.println("\nToken saved to: " + output.toAbsolutePath());
            } else if ("dec".equalsIgnoreCase(args[0])) {
                if (args.length != 3) {
                    usage();
                    System.exit(2);
                }
                char[] password = getPassword();
                try {
                    String plaintext = decrypt(readToken(args[1]), args[2], password);
                    System.out.println("\nDecrypted text = " + plaintext);
                } finally {
                    Arrays.fill(password, '\0');
                }
            } else {
                usage();
                System.exit(2);
            }
        } catch (AEADBadTagException e) {
            System.err.println("Decryption failed: authentication failed; token altered or wrong key.");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}


// Java compiler:       javac -d src src/exer5/JWE.java
// Encrypt message:     java -cp src exer5.JWE enc "Hello Alice" src/exer5/certificates-keys/end-entities/Alice_1.cer
// Decrypt message:     java -cp src exer5.JWE dec jwe-token.txt src/exer5/certificates-keys/pfx/Alice_1.pfx
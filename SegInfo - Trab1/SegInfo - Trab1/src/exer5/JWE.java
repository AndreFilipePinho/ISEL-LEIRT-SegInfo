package exer5;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import javax.crypto.*;
import javax.crypto.spec.*;



public class JWE {

    // Password to access the private key in the .pfx files
    private static final char[] DEFAULT_PRIVATE_KEY_PASSWORD = "changeit".toCharArray();

    // Name of the file where the jwe token will be stored and read
    private static final String TOKEN_FILE = "jwe-token.txt";

    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 128;

    private static final String ALG = "RSA-OAEP-256";
    private static final String ENC = "A256GCM";

    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder decoder = Base64.getUrlDecoder();

    private static final SecureRandom random = new SecureRandom();

    private static final OAEPParameterSpec OAEP =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);




    // =========================================================
    // ALÍNEA (a): AES-GCM
    // =========================================================

    // Returns ciphertext followed by the authentication tag.
    private static byte[] aesEncrypt(String text, byte[] aad, SecretKey key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String aesDecrypt(byte[] encrypted, byte[] aad, SecretKey key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        cipher.updateAAD(aad);
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    private static void testA() throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_SIZE);
        SecretKey key = generator.generateKey();

        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);

        byte[] aad = "test".getBytes(StandardCharsets.UTF_8);
        String message = "Hello Alice";

        byte[] encrypted = aesEncrypt(message, aad, key, iv);
        String decrypted = aesDecrypt(encrypted, aad, key, iv);

        System.out.println("Original text = " + message);
        System.out.println("Decrypted text = " + decrypted);
        System.out.println("AES-GCM test = " + message.equals(decrypted));
    }



    // =========================================================
    // ALÍNEA (b): RSA key transport
    // =========================================================

    private static byte[] rsaEncryptKey(SecretKey key, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP);
        return cipher.doFinal(key.getEncoded());
    }

    private static SecretKey rsaDecryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
        byte[] keyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void testB(String certificateFile, String pfxFile) throws Exception {

        PublicKey publicKey = loadCertificate(certificateFile).getPublicKey();
        PrivateKey privateKey = loadPrivateKey(pfxFile);

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_SIZE);
        SecretKey originalKey = generator.generateKey();

        byte[] encryptedKey = rsaEncryptKey(originalKey, publicKey);
        SecretKey recoveredKey = rsaDecryptKey(encryptedKey, privateKey);

        System.out.println("RSA key transport test = " + Arrays.equals(originalKey.getEncoded(), recoveredKey.getEncoded()));
    }



    // =========================================================
    // ALÍNEA (c): X.509 certificate and PFX private key
    // =========================================================

    private static X509Certificate loadCertificate(String filename) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        try (InputStream input = Files.newInputStream(Path.of(filename))) {
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(input);

            certificate.checkValidity();

            if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
                throw new Exception("Certificate must contain an RSA key.");
            }

            return certificate;
        }
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {

        KeyStore store = KeyStore.getInstance("PKCS12");

        try (InputStream input = Files.newInputStream(Path.of(filename))) {
            store.load(input, DEFAULT_PRIVATE_KEY_PASSWORD);
        }

        Enumeration<String> aliases = store.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (store.isKeyEntry(alias)) {
                Key key = store.getKey(alias, DEFAULT_PRIVATE_KEY_PASSWORD);

                if (key instanceof PrivateKey && "RSA".equalsIgnoreCase(key.getAlgorithm())) {

                    Certificate certificate = store.getCertificate(alias);

                    if (certificate instanceof X509Certificate) {
                        ((X509Certificate) certificate).checkValidity();
                    }

                    return (PrivateKey) key;
                }
            }
        }

        throw new Exception("No RSA private key found in the PFX.");
    }

    private static void testC(String certificateFile, String pfxFile) throws Exception {

        X509Certificate certificate = loadCertificate(certificateFile);
        PrivateKey privateKey = loadPrivateKey(pfxFile);

        System.out.println("Certificate subject = " + certificate.getSubjectX500Principal());
        System.out.println("Public key algorithm = " + certificate.getPublicKey().getAlgorithm());
        System.out.println("Private key algorithm = " + privateKey.getAlgorithm());
    }



    // =========================================================
    // ALÍNEA (d): complete JWE
    // =========================================================

    private static String encrypt(String text, String certificateFile) throws Exception {

        PublicKey publicKey = loadCertificate(certificateFile).getPublicKey();

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_SIZE);
        SecretKey aesKey = generator.generateKey();

        byte[] encryptedKey = rsaEncryptKey(aesKey, publicKey);

        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);

        String header = "{\"alg\":\"" + ALG + "\",\"enc\":\"" + ENC + "\"}";
        String protectedHeader = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // The protected header is the additional authenticated data.
        byte[] aad = protectedHeader.getBytes(StandardCharsets.US_ASCII);
        byte[] encrypted = aesEncrypt(text, aad, aesKey, iv);

        // JCA returns ciphertext followed by the GCM tag.
        int tagSize = TAG_SIZE / 8;
        byte[] ciphertext = Arrays.copyOfRange(encrypted, 0, encrypted.length - tagSize);
        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - tagSize, encrypted.length);

        return protectedHeader + "."
                + encoder.encodeToString(encryptedKey) + "."
                + encoder.encodeToString(iv) + "."
                + encoder.encodeToString(ciphertext) + "."
                + encoder.encodeToString(tag);
    }

    private static String decrypt(String token, String pfxFile) throws Exception {

        String[] parts = token.trim().split("\\.", -1);

        if (parts.length != 5) {
            throw new Exception("JWE token must contain five parts.");
        }

        String header = new String(decoder.decode(parts[0]), StandardCharsets.UTF_8);

        if (!header.equals("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}")) {
            throw new Exception("Unsupported JWE algorithms.");
        }

        byte[] encryptedKey = decoder.decode(parts[1]);
        byte[] iv = decoder.decode(parts[2]);
        byte[] ciphertext = decoder.decode(parts[3]);
        byte[] tag = decoder.decode(parts[4]);

        if (iv.length != IV_SIZE || tag.length != TAG_SIZE / 8) {
            throw new Exception("Invalid IV or authentication tag.");
        }

        // Join ciphertext and tag for AES-GCM decryption.
        byte[] encrypted = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encrypted, 0, ciphertext.length);
        System.arraycopy(tag, 0, encrypted, ciphertext.length, tag.length);

        PrivateKey privateKey = loadPrivateKey(pfxFile);
        SecretKey aesKey = rsaDecryptKey(encryptedKey, privateKey);

        byte[] aad = parts[0].getBytes(StandardCharsets.US_ASCII);
        return aesDecrypt(encrypted, aad, aesKey, iv);
    }




    // =========================================================
    // MAIN: choose which alínea to test
    // =========================================================

    public static void main(String[] args) {
        try {
            if (args.length == 1 && args[0].equals("a")) {
                testA();
            } else if (args.length == 3 && args[0].equals("b")) {
                testB(args[1], args[2]);
            } else if (args.length == 3 && args[0].equals("c")) {
                testC(args[1], args[2]);
            }

            else if (args.length == 3 && args[0].equals("enc")) {
                String token = encrypt(args[1], args[2]);
                Files.writeString(Path.of(TOKEN_FILE), token,
                        StandardCharsets.UTF_8);
                System.out.println("\nJWE token = " + token);
                System.out.println("\nSaved to " + TOKEN_FILE);
            }

            else if (args.length == 2 && args[0].equals("dec")) {
                String token = Files.readString(Path.of(TOKEN_FILE), StandardCharsets.UTF_8);
                System.out.println("\n Decrypted text = " + decrypt(token, args[1]));

            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}


// Java compiler:       javac -d src src/exer5/JWE.java
// Encrypt message:     java -cp src exer5.JWE enc "Hello Alice" src/exer5/certificates-keys/end-entities/Alice_1.cer
// Decrypt message:     java -cp src exer5.JWE dec src/exer5/certificates-keys/pfx/Alice_1.pfx
/*
 * @Author Justin Fulner
 */
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Receiver {
    private static int BUFFER_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        copyFile(new File("../KeyGen/symmetric.key"), new File("../Receiver/symmetric.key"));
        copyFile(new File("../KeyGen/YPrivate.key"), new File("../Receiver/YPrivate.key"));
        copyFile(new File("../Sender/message.rsacipher"), new File("../Receiver/message.rsacipher"));

        // read the keys from files
        PrivateKey yPriv = readPrivKeyFromFile("YPrivate.key");
        SecretKeySpec symKey = new SecretKeySpec(readSymmetricKey("./symmetric.key"), "AES");

        System.out.print("Enter the name of the message file: ");
        Scanner scan = new Scanner(System.in);
        String msgFile = scan.nextLine(); // plaintext M location

        // decrypt message.rsacipher
        decryptRSA(yPriv, "message.rsacipher");
        // decrypt Authentic Digital Digest
        byte[] ddd = decryptAES(separate(msgFile), symKey);
        // calculate digital digest of M
        byte[] Mdd = computeHash(msgFile);

        if (Arrays.equals(ddd, Mdd)) {
            System.out.print("\nAuthentication Successful.");
        }else {
            System.out.print("\nAuthentication Failed.");
        }
    }

    static byte[] computeHash(String fileName) throws Exception {
        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(fileName));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(bin, md);
        byte[] buff = new byte[BUFFER_SIZE];
        int i;
        do {
            i = bin.read(buff, 0, BUFFER_SIZE);
        }while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();

        byte[] hash = md.digest();

        System.out.println("\ndigital digest (hash value of M):");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        return hash;
    }

    static byte[] decryptAES(byte[] digest, SecretKeySpec key) throws Exception {
        String IV = "AAAAAAAAAAAAAAAA";
        BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream("message.dd"));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] decryptedHash = cipher.doFinal(digest);

        bo.write(decryptedHash);
        bo.close();

        // display decrypted digest
        System.out.println("\ndecrypted digital digest (SHA256(M)):");
        for (int k=0, j=0; k<decryptedHash.length; k++, j++) {
            System.out.format("%2X ", decryptedHash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        return decryptedHash;
    }

    static byte[] separate(String fileName) throws Exception {
        BufferedInputStream bin = new BufferedInputStream(new FileInputStream("message.add-msg"));
        BufferedOutputStream bout = new BufferedOutputStream(new FileOutputStream(fileName, true));
        byte[] b = new byte[BUFFER_SIZE];
        int i;
        byte[] dd = new byte[32];
        bin.read(dd, 0, 32);
        do {
            i = bin.read(b,0, BUFFER_SIZE);
            bout.write(b);

        }while (i == BUFFER_SIZE);
        //bout.write(b);

        System.out.println("\nEncrypted digest (En-SHA256(M)):");
        for (int k=0, j=0; k<dd.length; k++, j++) {
            System.out.format("%2X ", dd[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }

        bout.close();
        return dd;
    }

    static void decryptRSA(PrivateKey key, String cipherText) throws Exception {
        FileInputStream fin = new FileInputStream(cipherText);
        FileOutputStream fout = new FileOutputStream("message.add-msg", true);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        int rsaBufferSize = (BUFFER_SIZE / 8);
        byte[] buffer = new byte[rsaBufferSize];
        int i;

        cipher.init(Cipher.DECRYPT_MODE, key);
        do {
            i = fin.read(buffer, 0 , rsaBufferSize);
            byte[] decrypted = cipher.doFinal(buffer);
            fout.write(decrypted);
        }while(i == rsaBufferSize);

        fin.close();
        fout.close();
    }

    static void copyFile(File src, File dst) throws IOException {
        Files.copy(src.toPath(), dst.toPath());
    }

    static byte[] readSymmetricKey(String keyFilePath) throws IOException {
        Path loc = Paths.get(keyFilePath);
        return Files.readAllBytes(loc);
    }

    static PrivateKey readPrivKeyFromFile(String keyFileName) {

        InputStream in =
                Receiver.class.getResourceAsStream(keyFileName);

        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            /*
            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            */
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }
}

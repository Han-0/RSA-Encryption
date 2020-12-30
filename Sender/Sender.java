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
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Sender {
    private static int BUFFER_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        // copy the needed .key files
        copyFile(new File("../KeyGen/symmetric.key"), new File("../Sender/symmetric.key"));
        copyFile(new File("../KeyGen/YPublic.key"), new File("../Sender/YPublic.key"));

        // read the keys from the files
        PublicKey yPub = readPubKeyFromFile("YPublic.key");
        byte[] Kxy = readSymmetricKey("./symmetric.key");
        SecretKeySpec symKey = new SecretKeySpec(Kxy, "AES");

        // get the sender's input file 'M' and compute the digital digest
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter the name of the message file: ");
        String msgFile = scan.nextLine();
        byte[] mdd = computeHash(msgFile);
        // perform AES-En on SHA256(M) and append M to file
        encryptAES(symKey, mdd);
        appendMtoFile(msgFile);
        // perform the RSA encryption
        encryptRSA(yPub, "message.add-msg");
        //readAppended();

    }

    static void copyFile(File src, File dst) throws IOException {
        Files.copy(src.toPath(), dst.toPath());
    }

    static PublicKey readPubKeyFromFile(String keyFileName) {

        InputStream in =
                Sender.class.getResourceAsStream(keyFileName);

        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            /*
            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            */
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    static byte[] readSymmetricKey(String keyFilePath) throws IOException {
        Path loc = Paths.get(keyFilePath);
        return Files.readAllBytes(loc);
    }

    static byte[] computeHash(String msg) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(msg));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        byte[] buffer = new byte[BUFFER_SIZE];
        int i;
        do {
            i = file.read(buffer,0,BUFFER_SIZE);
        }while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();

        // save calculated message digest to file
        byte[] hash = md.digest();
        BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream("message.dd"));
        bo.write(hash);
        bo.close();

        // display digest
        System.out.println("\ndigital digest (hash value):");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        return hash;
    }

    static void encryptAES(SecretKeySpec key, byte[] dd) throws Exception {
        String IV = "AAAAAAAAAAAAAAAA";
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] cipherText = cipher.doFinal(dd);

        BufferedOutputStream bout = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
        bout.write(cipherText);
        bout.close();

        // display encrypted digest
        System.out.println("\nAES-En(SHA-256(M)):");
        for (int k=0, j=0; k<cipherText.length; k++, j++) {
            System.out.format("%2X ", cipherText[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
    }

    static void appendMtoFile(String s) throws Exception {
        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(s));
        BufferedOutputStream bout =
                new BufferedOutputStream(new FileOutputStream("message.add-msg", true));
        byte[] b = new byte[BUFFER_SIZE];
        int i;
        do {
            i = bin.read(b, 0, BUFFER_SIZE);
            bout.write(b);
        }while (i == BUFFER_SIZE);
        bout.write(b);
        bin.close();
        bout.close();
    }

    static void encryptRSA(PublicKey key, String fileName) throws Exception {
        FileInputStream fin = new FileInputStream(fileName);
        FileOutputStream fout = new FileOutputStream("message.rsacipher", true);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        int rsaBufferSize =(BUFFER_SIZE/8) - 11;
        byte[] b = new byte[rsaBufferSize];
        int i;

        cipher.init(Cipher.ENCRYPT_MODE, key);
        do {
            i = fin.read(b, 0, rsaBufferSize);
            byte[] C = cipher.doFinal(b);
            fout.write(C);

            if (i < rsaBufferSize) {
                byte[] b2 = new byte[i];
                fin.read(b2,0, i);
                C = cipher.update(b2);
                fout.write(C);
                cipher.doFinal();
            }
        }while (i == rsaBufferSize);

        System.out.println();
        fout.close();
        fin.close();
    }
}

/*
 * @Author Justin Fulner
 * program Generates public and private RSA keys for X and Y
 * X = sender
 * Y = receiver
 */
import java.io.*;

import java.math.BigInteger;

import java.security.*;

import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;

public class KeyGen {

    public static void main(String[] args) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits

        //Generate a pair of keys for x
        KeyPair xPair = generator.generateKeyPair();
        Key xPubKey = xPair.getPublic();
        Key xPrivKey = xPair.getPrivate();

        //Get modulus and exponent of the keys and save to files
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpec = factory.getKeySpec(xPubKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpec = factory.getKeySpec(xPrivKey, RSAPrivateKeySpec.class);

        saveToFile("XPublic.key", pubKSpec.getModulus(), pubKSpec.getPublicExponent());
        saveToFile("XPrivate.key", privKSpec.getModulus(), privKSpec.getPrivateExponent());

        //Generate pair of keys for y
        KeyPair yPair = generator.generateKeyPair();
        Key yPubKey = yPair.getPublic();
        Key yPrivKey = yPair.getPrivate();

        RSAPublicKeySpec yPubKSpec = factory.getKeySpec(yPubKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec yPrivKSpec = factory.getKeySpec(yPrivKey, RSAPrivateKeySpec.class);

        saveToFile("YPublic.key", yPubKSpec.getModulus(), yPubKSpec.getPublicExponent());
        saveToFile("YPrivate.key", yPrivKSpec.getModulus(), yPrivKSpec.getPrivateExponent());

        //Get the symmetric key from user and save to a file
        Scanner scan = new Scanner(System.in);
        String s;
        do {
            System.out.print("Enter a 16 character key: ");
            s = scan.nextLine();
        }while (s.length() != 16);

        try {
            FileOutputStream out = new FileOutputStream("symmetric.key");
            byte[] Kxy = s.getBytes("UTF-8");
            out.write(Kxy);
            out.close();
            for (int i = 0; i < Kxy.length; i++) System.out.print(String.format("0x%02X",Kxy[i]) + " ");
        }catch (Exception e) {System.out.print(e);}
    }

    public static void saveToFile(String fileName,
                                  BigInteger mod, BigInteger exp) throws IOException {

        System.out.println("Write to " + fileName + ": modulus = " +
                mod.toString() + ", exponent = " + exp.toString() + "\n");

        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

}

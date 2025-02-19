package server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.xml.bind.DatatypeConverter;

public class HashUtil {
    private static final String SHA2_ALGORITHM = "SHA-256";

    public static String generateRandomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secure_random
                = new SecureRandom();
        secure_random.nextBytes(salt);
        return DatatypeConverter.printHexBinary(salt);
    }

    public static String generateHash(String input) throws IOException {
        ByteArrayOutputStream byte_Stream = new ByteArrayOutputStream();
        byte_Stream.write(input.getBytes());

        byte[] valueToHash = byte_Stream.toByteArray();
        try{
            MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGORITHM);
            return DatatypeConverter.printHexBinary(messageDigest.digest(valueToHash));
        } catch (NoSuchAlgorithmException n) {
            System.out.println("NoSuchAlgorithmException: " + n.getMessage());
        }
        return null;
    }

    public static BigInteger computeX(String salt, String login, String password) throws IOException {
        //x = H(s | H ( I | ":" | p) ).
        String hashLoginPassword = generateHash(login + ":" + password);
        String hashSaltLoginPassword = generateHash(salt + hashLoginPassword);
        return new BigInteger(hashSaltLoginPassword, 16);
    }
}

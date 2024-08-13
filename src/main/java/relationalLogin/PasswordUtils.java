package relationalLogin;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.DigestUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PasswordUtils {
    // these should match the values specified by the front-end application
    public static final String SHA512_PREFIX = "$6$";
    public static final String SHA512_ROUNDS = "656000";
    public static final String SHA256_PREFIX = "$5$";
    public static final String SHA256_ROUNDS = "535000";
    public static final String BCRYPT_PREFIX = "$2b$";
    public static final String BCRYPT_ROUNDS = "12";
    public static final String MD5_PREFIX = "$1$";

    private static final Logger logger = LoggerFactory.getLogger(DBLogin.class.getName());
    private static final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();
    private static PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // method to hash the password using the specified algorithm
    public static String hashPassword(byte[] password, String salt, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("hashPassword()  Password: " + new String(password));
        logger.debug("hashPassword()  Password Bytes: " + Arrays.toString(password));
        logger.debug("hashPassword() Salt: " + salt);
        logger.debug("hashPassword() Algorithm: " + algorithm);

        // String hashedPassword = new String();
        // String extractedSalt = new String();
        
        switch (algorithm.toLowerCase()) {
            case "bcrypt":
                return BCrypt.hashpw(new String(password), salt);
            case "crypt":
                return Crypt.crypt(password, salt);
            default:
                MessageDigest md = MessageDigest.getInstance(algorithm);
                byte[] hashedBytes = md.digest((new String(password) + salt).getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : hashedBytes) {
                    sb.append(String.format("%02x", b));
                }
                logger.debug("hashPassword()  Hashed Password: " + sb.toString());
                return sb.toString();
        }
    }
    
    // method to verify the password
    public static boolean checkPassword(byte[] password, String storedHash, String salt, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {

        logger.debug("checkPassword() Password: " + new String(password));
        logger.debug("checkPassword() Password Bytes: " + Arrays.toString(password));
        logger.debug("checkPassowrd() Salt: " + salt);
        logger.debug("checkPassword() Algorithm: " + algorithm);
        logger.debug("checkPassword() Stored Hash: " + storedHash);

        if (algorithm.equalsIgnoreCase("crypt")) {
            logger.debug("checkPassword() crypt algorithm: " + whichCryptAlgorithm(storedHash));
        }

        if (algorithm == null || algorithm.isEmpty()) {
            logger.debug("No hashing algorithm specified, trying string match");
            return storedHash.equals(new String(password));
        }
        
        String hashedPassword = hashPassword(password, salt, algorithm);
        logger.debug("checkPassword() Hashed password: " + hashedPassword);

        logger.debug("checkPassword() Stored Hash:     " + storedHash);
        logger.debug("checkPassword() Hashed Password: " + hashedPassword);
        logger.debug("checkPassword() Stored Hash Length: " + storedHash.length());
        logger.debug("checkPassword() Hashed Password Length: " + hashedPassword.length());

        logger.debug("checkPassword() Stored Hash Bytes:     " + Arrays.toString(storedHash.getBytes()));
        logger.debug("checkPassword() Hashed Password Bytes: " + Arrays.toString(hashedPassword.getBytes()));

        boolean isMatch = storedHash.equals(hashedPassword);
        logger.debug("checkPassword() Passwords match: " + isMatch);
        return isMatch;
    }

    private static String whichCryptAlgorithm (String storedHash) throws IllegalArgumentException {
        if (storedHash.startsWith(SHA512_PREFIX)) {
            return "SHA-512";
        } else if (storedHash.startsWith(SHA256_PREFIX)) {
            return "SHA-256";
        } else if (storedHash.startsWith(MD5_PREFIX)) {
            return "MD5";
        } else if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
            return "BCrypt";
        } else if (storedHash.length() == 13) {
            return "DES";
        } else {
            logger.debug("Stored hash: " + storedHash);
            throw new IllegalArgumentException("Unknown hash algorithm");
        }
    }

    // Helper method to extract the salt from the stored hash
    // private static String extractSaltFromCryptString(String storedHash) {
    //     switch (whichCryptAlgorithm(storedHash)) {
    //         case "SHA-512":
    //         case "SHA-256":
    //             // Check if the salt contains the "rounds=" segment
    //             int roundsIndex = storedHash.indexOf("rounds=");
    //             if (roundsIndex != -1) {
    //                 // Find the end of the rounds segment
    //                 int endOfRounds = storedHash.indexOf('$', roundsIndex);
    //                 // Find the next '$' after the end of the rounds segment
    //                 int nextDollarIndex = storedHash.indexOf('$', endOfRounds + 1);
    //                 return storedHash.substring(0, nextDollarIndex + 1);
    //             } else {
    //                 // Assuming the salt is the part of the stored hash up to the third '$' character
    //                 int thirdDollarIndex = storedHash.indexOf('$', storedHash.indexOf('$', storedHash.indexOf('$') + 1) + 1);
    //                 return storedHash.substring(0, thirdDollarIndex + 1);
    //             }
    //         case "BCrypt":
    //             // For bcrypt, the salt is the first 29 characters
    //             return storedHash.substring(0, 29);
    //         case "MD5":
    //             // For MD5, the salt is between the second and third '$' characters
    //             int secondDollarIndex = storedHash.indexOf('$', storedHash.indexOf('$') + 1);
    //             return storedHash.substring(0, storedHash.indexOf('$', secondDollarIndex + 1) + 1);
    //         case "DES":
    //             // For DES, the salt is the first two characters
    //             return storedHash.substring(0, 2);
    //         default:
    //             return storedHash.substring(0, storedHash.indexOf("$", storedHash.indexOf("$") + 1) + 1);
    //     }
    // }
}
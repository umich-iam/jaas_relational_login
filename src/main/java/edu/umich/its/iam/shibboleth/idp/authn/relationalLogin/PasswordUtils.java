package edu.umich.its.iam.shibboleth.idp.authn.relationalLogin;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.DigestUtils;


public class PasswordUtils {
    private static final Logger logger = Logger.getLogger(DBLogin.class.getName());
    private static final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();
    private static PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    public static String hashPassword(String input, String hashingAlg) throws NoSuchAlgorithmException {
		MessageDigest mDigest = MessageDigest.getInstance(hashingAlg);
		byte[] result = mDigest.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
		}

		return sb.toString();
	}

    public static String hashPasswordNew(String password, String hashingAlg) {
        switch (hashingAlg) {
            case "bcrypt":
                return bcryptEncoder.encode(password);
            case "crypt":
                return Crypt.crypt(password);
            // Add cases for other algorithms if needed
            default:
                throw new IllegalArgumentException("Unsupported hashing algorithm: " + hashingAlg);
        }
    }

    // Method to try hashing the password
    public static boolean tryHashingPassword(String password, String storedHash, String salt, String hashingAlg) {
        String tpwd = new String();

        try {
            logger.log(Level.SEVERE, "I think this password was hashed using: " + guessHashingAlg(storedHash));
        } catch (IllegalArgumentException e) {
            logger.log(Level.SEVERE, "Error: " + e.getMessage());
        }
        
        try {
            if (hashingAlg != null && !hashingAlg.isEmpty()) {
                if (hashingAlg.toLowerCase().equals("bcrypt")) {
                    tpwd = new String(password);
                    String storedHashBcrypt = "$2a" + storedHash.substring(3);
                    return passwordEncoder.matches(tpwd, storedHashBcrypt);
                } else if (hashingAlg.toLowerCase().equals("md5crypt")) {
                    tpwd = password;
                    return storedHash.equals(Md5Crypt.md5Crypt(tpwd.getBytes(), storedHash));
                } else {
                    tpwd = hashPassword(password + salt, hashingAlg);
                    return storedHash.toLowerCase().equals(tpwd.toLowerCase());
                }
            } else {
                tpwd = password;
                return storedHash.equals(tpwd);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Hashing algorithm not found", e);
            return false;
        }
    }

    public static boolean checkPassword(String rawPassword, String hashedPassword, String hashingAlg) throws IllegalArgumentException {
        switch (hashingAlg) {
            case "bcrypt":
                return bcryptEncoder.matches(rawPassword, hashedPassword);
            case "crypt":
                return Crypt.crypt(rawPassword, hashedPassword).equals(hashedPassword);
            // Add cases for other algorithms if needed
            default:
                throw new IllegalArgumentException("Unsupported hashing algorithm: " + hashingAlg);
        }
    }

    // try to programmatically determine the hashing algorithm used
    private static String guessHashingAlg(String password) {
        logger.log(Level.SEVERE, "provided hash: " + password);
    
        if (!password.startsWith("$")) {
            return "crypt";
        }
        if (password.startsWith("$6$")) {
            return "SHA-512";
        } else if (password.startsWith("$5$")) {
            return "SHA-256";
        } else if (password.startsWith("$4$")) {
            return "SHA-1";
        } else if (password.startsWith("$2a$") || password.startsWith("$2b$") || password.startsWith("$2y$")) {
            return "bcrypt";
        } else if (password.startsWith("$1$")) {
            return "md5crypt";
        } else {
            logger.log(Level.WARNING, "Unknown hashing algorithm prefix in password: " + password);
            throw new IllegalArgumentException("Unknown hashing algorithm prefix in password: " + password);
        }
    }
}

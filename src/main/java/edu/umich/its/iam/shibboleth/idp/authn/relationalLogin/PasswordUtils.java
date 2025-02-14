package edu.umich.its.iam.shibboleth.idp.authn.relationalLogin;

import org.springframework.security.crypto.bcrypt.BCrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.digest.Crypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for password-related operations, such as hashing and salt generation.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Note: Namespace changed to edu.umich.it.iam.shibboleth.idp.authn.relationalLogin for organizational purposes.
 */


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

    // method to hash the password using the specified algorithm
    public static String hashPassword(byte[] password, String salt, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
        if (algorithm == null || algorithm.isEmpty()) {
            logger.debug("No hashing algorithm specified, trying string match");
            return storedHash.equals(new String(password));
        }

        try {
            if (algorithm.equalsIgnoreCase("crypt")) {
                logger.debug("checkPassword() crypt algorithm: " + whichCryptAlgorithm(storedHash));
            }
        } catch (IllegalArgumentException e) {
            logger.error("checkPassword() " + e.getMessage());
            return false;
        }

        String hashedPassword = hashPassword(password, salt, algorithm);
        boolean isMatch = storedHash.equals(hashedPassword);
        logger.debug("checkPassword() Passwords match: " + isMatch);
        return isMatch;
    }

    // This is used for logging and test cases and could probably be removed
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

	// Generate a random salt for SHA-256 / SHA-512 crypt
	public static String generateRandomSalt() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		StringBuilder sb = new StringBuilder();
		for (byte b : salt) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}

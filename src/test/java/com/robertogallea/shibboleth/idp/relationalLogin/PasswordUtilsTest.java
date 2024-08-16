package com.robertogallea.shibboleth.idp.relationalLogin;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.MockitoAnnotations;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.apache.commons.codec.digest.DigestUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

public class PasswordUtilsTest {

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testHashPasswordWithBCrypt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = BCrypt.gensalt();
        System.err.println("bcrypt salt: " + salt);
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "bcrypt");
        System.err.println("bcrypt hashedPassword: " + hashedPassword);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertTrue(hashedPassword.startsWith("$2a$"), "Hashed password should start with $2a$ indicating BCrypt");
    }

    @Test
    public void testHashPasswordWithCryptSha512() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.SHA512_PREFIX + "rounds=" + PasswordUtils.SHA512_ROUNDS + "$"
                + DigestUtils.sha512Hex("salt");
        System.err.println("sha512 crypt salt: " + salt);
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");
        System.err.println("sha512 crypt hashedPassword: " + hashedPassword);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertTrue(hashedPassword.startsWith("$6"), "Hashed password should start with $6$ indicating SHA-512 crypt");
    }

    @Test
    public void testHashPasswordWithCryptSha256() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.SHA256_PREFIX + "rounds=" + PasswordUtils.SHA256_ROUNDS + "$"
                + DigestUtils.sha256Hex("salt");
        System.err.println("sha256 crypt salt: " + salt);
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");
        System.err.println("sha256 crypt hashedPassword: " + hashedPassword);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertTrue(hashedPassword.startsWith("$5$"), "Hashed password should start with $5$ indicating SHA-256 crypt");
    }

    @Test
    public void testHashPasswordWithCryptMd5() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.MD5_PREFIX + DigestUtils.md5Hex("salt");
        System.err.println("md5 crypt salt: " + salt);
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");
        System.err.println("md5 crypt hashedPassword: " + hashedPassword);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertTrue(hashedPassword.startsWith("$1$"), "Hashed password should start with $1$ indicating MD5 crypt");
    }

    @Test
    public void testHashPasswordWithCryptDES() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = generateDESSalt();
        System.err.println("DES crypt salt: " + salt);
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");
        System.err.println("DES crypt hashedPassword: " + hashedPassword);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertTrue(hashedPassword.startsWith(salt), "Hashed password should start with the DES salt");
    }

    @Test
    public void testHashPasswordWithSha512() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha512Hex("salt");
        System.err.println("sha512 salt: " + salt);

        // Call hashPassword with SHA-512 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-512");
        System.err.println("sha512 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertNotNull(hashedPassword, "Hashed password should not be null");
    }

    @Test
    public void testHashPasswordWithSha256() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha256Hex("salt");
        System.err.println("sha256 salt: " + salt);

        // Call hashPassword with SHA-256 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-256");
        System.err.println("sha256 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertNotNull(hashedPassword, "Hashed password should not be null");
    }

    @Test
    public void testHashPasswordWithSha1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha1Hex("salt");
        System.err.println("sha1 salt: " + salt);

        // Call hashPassword with SHA-1 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-1");
        System.err.println("sha1 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertNotNull(hashedPassword, "Hashed password should not be null");
    }

    @Test
    public void testHashPasswordWithInvalidAlgorithm() {
        String password = "password123";
        String salt = "salt";

        assertThrows(NoSuchAlgorithmException.class, () -> {
            PasswordUtils.hashPassword(password.getBytes(), salt, "invalidAlgorithm");
        });
    }

    @Test
    public void testCheckPasswordWithBCrypt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = BCrypt.gensalt();
        String hashedPassword = BCrypt.hashpw(password, salt);

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "bcrypt"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithCryptSha512() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.SHA512_PREFIX + "rounds=" + PasswordUtils.SHA512_ROUNDS + "$"
                + DigestUtils.sha512Hex("salt");
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "crypt"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithCryptSha256() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.SHA256_PREFIX + "rounds=" + PasswordUtils.SHA256_ROUNDS + "$"
                + DigestUtils.sha512Hex("salt");
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "crypt"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithCryptMd5() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.MD5_PREFIX + DigestUtils.md5Hex("salt");
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "crypt"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithCryptDES() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.MD5_PREFIX + DigestUtils.md5Hex("salt");
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "crypt"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithCleartext() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String storedPassword = "password123";

        assertTrue(PasswordUtils.checkPassword(password.getBytes(), storedPassword, "", ""),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithSha512() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha512Hex("salt");
        System.err.println("sha512 salt: " + salt);

        // Call hashPassword with SHA-512 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-512");
        System.err.println("sha512 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "SHA-512"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithSha256() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha256Hex("salt");
        System.err.println("sha256 salt: " + salt);

        // Call hashPassword with SHA-256 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-256");
        System.err.println("sha256 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "SHA-256"),
                "Passwords should match");
    }

    @Test
    public void testCheckPasswordWithSha1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = DigestUtils.sha1Hex("salt");
        System.err.println("sha1 salt: " + salt);

        // Call hashPassword with SHA-1 algorithm
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "SHA-1");
        System.err.println("sha1 hashedPassword: " + hashedPassword);

        // Verify that the hashed password is not null
        assertTrue(PasswordUtils.checkPassword(password.getBytes(), hashedPassword, salt, "SHA-1"),
                "Passwords should match");
    }

    @Test
    public void testWhichCryptAlgorithm() throws Exception {
        // Use reflection to access the private method
        Method method = PasswordUtils.class.getDeclaredMethod("whichCryptAlgorithm", String.class);
        method.setAccessible(true);

        // Test SHA-512
        String sha512Hash = "$6$rounds=656000$2e3fce77cf8c4c7478a96d207c1c39715892cac84a18cbec9b634f4bc22b390b48cd30a4df2e7ebbaee65c346a662c5be2d12441322f7a4bac821a382c4af091";
        assertEquals("SHA-512", method.invoke(null, sha512Hash));

        // Test SHA-256
        String sha256Hash = "$5$rounds=5000$abcdefghijklmnopqrstuvwx";
        assertEquals("SHA-256", method.invoke(null, sha256Hash));

        // Test MD5
        String md5Hash = "$1$abcdefgh$ijklmnopqrstuvwxyz123456";
        assertEquals("MD5", method.invoke(null, md5Hash));

        // Test BCrypt
        String bcryptHash = "$2a$10$abcdefghijklmnopqrstuvwx";
        assertEquals("BCrypt", method.invoke(null, bcryptHash));

        // Test DES
        String desHash = "abcdefghijklm";
        assertEquals("DES", method.invoke(null, desHash));

        // Test unknown algorithm
        String unknownHash = "$9$unknownhash";
        try {
            method.invoke(null, unknownHash);
            fail("Expected IllegalArgumentException to be thrown");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
            assertEquals("Unknown hash algorithm", e.getCause().getMessage());
        }
    }

    private String generateDESSalt() {
        SecureRandom random = new SecureRandom();
        char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./".toCharArray();
        StringBuilder salt = new StringBuilder();
        for (int i = 0; i < 2; i++) {
            salt.append(chars[random.nextInt(chars.length)]);
        }
        return salt.toString();
    }
}
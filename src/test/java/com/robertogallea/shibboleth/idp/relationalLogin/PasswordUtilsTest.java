package com.robertogallea.shibboleth.idp.relationalLogin;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.MockitoAnnotations;

import java.security.NoSuchAlgorithmException;
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
        String salt = PasswordUtils.BCRYPT_PREFIX + PasswordUtils.BCRYPT_ROUNDS + "$" + BCrypt.gensalt();
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "bcrypt");

        assertNotNull(hashedPassword);
        assertTrue(BCrypt.checkpw(password, hashedPassword));
    }

    @Test
    public void testHashPasswordWithCrypt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String password = "password123";
        String salt = PasswordUtils.SHA512_PREFIX + PasswordUtils.SHA512_ROUNDS + "$" + DigestUtils.sha512Hex("salt");
        String hashedPassword = PasswordUtils.hashPassword(password.getBytes(), salt, "crypt");

        assertNotNull(hashedPassword);
        assertTrue(hashedPassword.startsWith(PasswordUtils.SHA512_PREFIX));
    }

    @Test
    public void testHashPasswordWithInvalidAlgorithm() {
        String password = "password123";
        String salt = "salt";

        assertThrows(NoSuchAlgorithmException.class, () -> {
            PasswordUtils.hashPassword(password.getBytes(), salt, "invalidAlgorithm");
        });
    }
}
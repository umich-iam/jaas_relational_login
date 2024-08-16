package com.robertogallea.shibboleth.idp.authn.relationalLogin;

import org.junit.jupiter.api.Test;
import javax.security.auth.callback.*;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleCallbackHandlerTest {

    @Test
    public void testHandleNameCallback() throws Exception {
        String expectedUsername = "testUser";
        SimpleCallbackHandler handler = new SimpleCallbackHandler(expectedUsername, "testPassword".toCharArray());

        NameCallback nameCallback = new NameCallback("username");
        Callback[] callbacks = new Callback[]{nameCallback};

        handler.handle(callbacks);

        assertEquals(expectedUsername, nameCallback.getName());
    }

    @Test
    public void testHandlePasswordCallback() throws Exception {
        char[] expectedPassword = "testPassword".toCharArray();
        SimpleCallbackHandler handler = new SimpleCallbackHandler("testUser", expectedPassword);

        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        Callback[] callbacks = new Callback[]{passwordCallback};

        handler.handle(callbacks);

        assertArrayEquals(expectedPassword, passwordCallback.getPassword());
    }

    @Test
    public void testHandleUnsupportedCallback() {
        SimpleCallbackHandler handler = new SimpleCallbackHandler("testUser", "testPassword".toCharArray());

        Callback unsupportedCallback = new Callback() {};
        Callback[] callbacks = new Callback[]{unsupportedCallback};

        assertThrows(UnsupportedCallbackException.class, () -> {
            handler.handle(callbacks);
        });
    }
}
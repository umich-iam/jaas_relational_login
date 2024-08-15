// $Id: Utils.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.robertogallea.shibboleth.idp.relationalLogin;

import java.security.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for com.tagish.auth.*. All the methods in here are static
 * so Utils should never be instantiated.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class Utils
{
	private static final Logger logger = LoggerFactory.getLogger(Utils.class);

	static {
        // Static initializer block for SLF4J
        logger.info("SLF4J Logger initialized in Utils class");
    }

	/**
	 * Can't make these: all the methods are static
	 */
	private Utils()
	{
	}

	/**
	 * Zero the contents of the specified array. Typically used to
	 * erase temporary storage that has held plaintext passwords
	 * so that we don't leave them lying around in memory.
	 *
	 * @param pwd the array to zero
	 */
	public static void smudge(char pwd[])
	{
		if (null != pwd) {
			for (int b = 0; b < pwd.length; b++) {
				pwd[b] = 0;
			}
		}
	}

	/**
	 * Zero the contents of the specified array.
	 *
	 * @param pwd the array to zero
	 */
	public static void smudge(byte pwd[])
	{
		if (null != pwd) {
			for (int b = 0; b < pwd.length; b++) {
				pwd[b] = 0;
			}
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

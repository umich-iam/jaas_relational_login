// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package relationalLogin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;

/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin {
	protected String dbDriver;
	protected String dbURL;
	protected String dbUser;
	protected String dbPassword;
	protected String userTable;
	protected String userColumn;
	protected String passColumn;
	protected String saltColumn;
	protected String lastLoginColumn;
	protected String where;

	private Connection con;

	private static final Logger logger = Logger.getLogger(DBLogin.class.getName());

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null)
			throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null)
			throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
			throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		userTable = getOption("userTable", "User");
		userColumn = getOption("userColumn", "user_name");
		passColumn = getOption("passColumn", "user_passwd");
		saltColumn = getOption("saltColumn", "");
		lastLoginColumn = getOption("lastLoginColumn", "");
		where = getOption("where", "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";

		// Initialize the database connection
		try {
			Class.forName(dbDriver);

			if (dbUser != null)
				con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
				con = DriverManager.getConnection(dbURL);
		} catch (ClassNotFoundException | SQLException e) {
			throw new Error("Failed to initialize database connection", e);
		}
	}

	public void closeConnection() {
		if (con != null) {
			try {
				con.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

	protected synchronized Vector<TypedPrincipal> validateUser(String username, char password[]) throws LoginException {
		try {
			// Retrieve the stored hashed password from the database
			String[] passwordData = getPasswordFromDatabase(username);
			String upwd = passwordData[0];
			String salt = passwordData[1];
	
			// Check the password
			String tpwd = new String();
	
			String hashingAlg = getOption("hashAlgorithm", null);
	
			if (!PasswordUtils.tryHashingPassword(new String(password), upwd, salt, hashingAlg)) {
				throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
			}

			// If password is valid, update the last login timestamp
			if (!lastLoginColumn.equals(""))
				updateLastLogin(username);
	
			Vector<TypedPrincipal> p = new Vector<>();
			return p;
		} catch (SQLException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
	}

	private String[] getPasswordFromDatabase(String username) throws SQLException, FailedLoginException, LoginException {
		String stmt = new String();
		stmt = "SELECT " + passColumn + (!saltColumn.equals("") ? ("," + saltColumn) : "") + " FROM " + userTable +
				" WHERE " + userColumn + "=?" + where;

		// Log the full SQL
		String fullSql = stmt.replaceFirst("\\?", "'" + username + "'");
		logger.log(Level.SEVERE, "Executing SQL: " + fullSql);

		try (PreparedStatement psu = con.prepareStatement(stmt)) {
			psu.setString(1, username);
			try (ResultSet rsu = psu.executeQuery()) {
				if (!rsu.next()) {
					throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
				}

				String password = rsu.getString(1);
				String salt = (!saltColumn.equals("") ? rsu.getString(2) : "");
				return new String[]{password, salt};
			} catch (SQLException e) {
				// Handle SQL exception
				e.printStackTrace();
				throw new LoginException("Error reading user database (" + e.getMessage() + ")");
			}
		}
	}

	private void updateLastLogin(String username) {
		// SQL statement to update the last_login column
		String stmt = "UPDATE " + userTable + " SET " + lastLoginColumn + " = CURRENT_TIMESTAMP WHERE " + userColumn + "= ?";
	
		try (PreparedStatement psu = con.prepareStatement(stmt)) {
			psu.setString(1, username);
			psu.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}

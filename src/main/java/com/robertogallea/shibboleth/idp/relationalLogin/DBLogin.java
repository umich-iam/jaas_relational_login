// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.robertogallea.shibboleth.idp.relationalLogin;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.sql.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static final Logger logger = LoggerFactory.getLogger(DBLogin.class.getName());

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

		userTable       = getOption("userTable",       "User");
		userColumn      = getOption("userColumn",      "user_name");
		passColumn      = getOption("passColumn",      "user_passwd");
		saltColumn      = getOption("saltColumn",      "");
		lastLoginColumn	= getOption("lastLoginColumn", "");
		where           = getOption("where",           "");

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
				throw new Error("Error closing database connection (" + e.getMessage() + ")");
			}
		}
	}

	protected synchronized Vector<TypedPrincipal> validateUser(String username, char password[]) throws LoginException {
		try {
			// Retrieve the stored hashed password from the database
			String[] passwordData = getPasswordFromDatabase(username);
			String storedHash = passwordData[0];
			String salt = passwordData[1];
	
			String hashAlgorithm = getOption("hashAlgorithm", null);
			try {
				// Convert char[] password to byte[]
				byte[] passwordBytes = new String(password).getBytes();

				if (!PasswordUtils.checkPassword(passwordBytes, storedHash, salt, hashAlgorithm)) {
					throw new FailedLoginException(getOption("errorMessage", "Invalid details"));	
				}

				if (hashAlgorithm.equalsIgnoreCase("crypt") && getOption("rehashCryptEnabled", false)) {
					// Check if the password needs to be rehashed					
					if (!storedHash.startsWith(PasswordUtils.SHA512_PREFIX)) {
						// Update the stored password with the new hash and salt
						passwordBytes = new String(password).getBytes();
						String newSalt = PasswordUtils.SHA512_PREFIX + "rounds=" + PasswordUtils.SHA512_ROUNDS + "$" + Utils.generateRandomSalt();
						String newHash = PasswordUtils.hashPassword(passwordBytes, newSalt, hashAlgorithm);
						updateStoredPassword(username, newHash);
					}
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new FailedLoginException(getOption("errorMessage", "Invalid details"));	
			}

			// If password is valid, update the last login timestamp
			if (!lastLoginColumn.equals(""))
				updateLastLogin(username);
	
			Vector<TypedPrincipal> p = new Vector<>();
			return p;
		} catch (SQLException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} finally {
            closeConnection(); // Ensure the connection is closed
		}
	}

	private String[] getPasswordFromDatabase(String username) throws SQLException, FailedLoginException, LoginException {
		String sql = new String();
		sql = "SELECT " + passColumn + (!saltColumn.equals("") ? ("," + saltColumn) : "") + " FROM " + userTable +
				" WHERE " + userColumn + "=?" + where;

		// Log the full SQL
		String fullSql = sql.replaceFirst("\\?", "'" + username + "'");
		logger.debug("Executing SQL: " + fullSql);

		try (PreparedStatement preparedStatment = con.prepareStatement(sql)) {
			preparedStatment.setString(1, username);
			try (ResultSet resultSet = preparedStatment.executeQuery()) {
				if (!resultSet.next()) {
					throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
				}

				String password = resultSet.getString(1);
				String salt = (!saltColumn.equals("") ? resultSet.getString(2) : "");
				return new String[]{password, salt};
			} catch (SQLException e) {
				// Handle SQL exception
				e.printStackTrace();
				throw new LoginException("Error reading user database (" + e.getMessage() + ")");
			}
		}
	}

	private void updateStoredPassword(String username, String passwordHash) throws SQLException{
		logger.debug("Updating password for user: " + username);

		// SQL statement to update the password and salt columns
		String sql = "UPDATE " + userTable + " SET " + passColumn + " = ? WHERE " + userColumn + "= ?";
	
		try (PreparedStatement preparedStatment = con.prepareStatement(sql)) {
			preparedStatment.setString(1, passwordHash);
			preparedStatment.setString(2, username);
			preparedStatment.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new SQLException("Error updating user database (" + e.getMessage() + ")");
		}
	}

	private void updateLastLogin(String username) throws SQLException {
		logger.debug("Updating last login for user: " + username);

		// SQL statement to update the last_login column
		String sql = getUpdateLastLoginSQL();

		try (PreparedStatement preparedStatment = con.prepareStatement(sql)) {
			preparedStatment.setString(1, username);
			preparedStatment.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new SQLException("Error updating user database (" + e.getMessage() + ")");
		}
	}

    public String getUpdateLastLoginSQL() throws SQLException {
        String dbType = getDbType();
        String sql;

        switch (dbType) {
            case "MySQL":
            case "PostgreSQL":
            case "SQLite":
                sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = CURRENT_TIMESTAMP WHERE " + userColumn + " = ?";
                break;
            case "Oracle":
                sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = SYSDATE WHERE " + userColumn + " = ?";
                break;
            case "SQLServer":
                sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = GETDATE() WHERE " + userColumn + " = ?";
                break;
            default:
                throw new UnsupportedOperationException("Unsupported DBMS: " + dbType);
        }

        return sql;
    }

	private String getDbType() throws SQLException {
        String driverName = dbDriver.toLowerCase();

        if (driverName.contains("mysql")) {
            return "MySQL";
        } else if (driverName.contains("postgresql")) {
            return "PostgreSQL";
        } else if (driverName.contains("oracle")) {
            return "Oracle";
        } else if (driverName.contains("sqlserver")) {
            return "SQLServer";
        } else if (driverName.contains("sqlite")) {
            return "SQLite";
        } else {
            throw new UnsupportedOperationException("Unsupported DBMS: " + driverName);
        }
    }
}

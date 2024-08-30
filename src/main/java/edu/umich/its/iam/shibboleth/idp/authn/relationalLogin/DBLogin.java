// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package edu.umich.its.iam.shibboleth.idp.authn.relationalLogin;

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
 * Originally authored by Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * Modified and extended by Roberto Gallea
 * Further modifications by ITS Identity and Access Management, University of Michigan <its.iam.infrastructure.developers@umich.edu>
 * @version 1.1.0
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

public class DBLogin extends SimpleLogin {
	private String dbDriver;
	private String dbURL;
	private String dbUser;
	private String dbPassword;
	private String userTable;
	private String userColumn;
	private String passColumn;
	private String saltColumn;
	private String lastLoginColumn;
	private String where;

	private static final Logger logger = LoggerFactory.getLogger(DBLogin.class.getName());

	// Getter and Setter methods
	public String getDbDriver() {
		return dbDriver;
	}

	public void setDbDriver(String dbDriver) {
		this.dbDriver = dbDriver;
	}

	public String getDbURL() {
		return dbURL;
	}

	public void setDbURL(String dbURL) {
		this.dbURL = dbURL;
	}

	public String getDbUser() {
		return dbUser;
	}

	public void setDbUser(String dbUser) {
		this.dbUser = dbUser;
	}

	public String getDbPassword() {
		return dbPassword;
	}

	public void setDbPassword(String dbPassword) {
		this.dbPassword = dbPassword;
	}

	public String getUserTable() {
		return userTable;
	}

	public void setUserTable(String userTable) {
		this.userTable = userTable;
	}

	public String getUserColumn() {
		return userColumn;
	}

	public void setUserColumn(String userColumn) {
		this.userColumn = userColumn;
	}

	public String getPassColumn() {
		return passColumn;
	}

	public void setPassColumn(String passColumn) {
		this.passColumn = passColumn;
	}

	public String getSaltColumn() {
		return saltColumn;
	}

	public void setSaltColumn(String saltColumn) {
		this.saltColumn = saltColumn;
	}

	public String getLastLoginColumn() {
		return lastLoginColumn;
	}

	public void setLastLoginColumn(String lastLoginColumn) {
		this.lastLoginColumn = lastLoginColumn;
	}

	public String getWhere() {
		return where;
	}

	public void setWhere(String where) {
		this.where = where;
	}

	// Method to get a connection
	protected Connection getConnection(String url, String user, String password) throws SQLException {
		return DriverManager.getConnection(url, user, password);
	}

	// Method to set a connection for testing purposes
	private Connection testConnection;

	protected void setTestConnection(Connection connection) {
		this.testConnection = connection;
	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		super.initialize(subject, callbackHandler, sharedState, options);

		String dbDriver = getOption("dbDriver", null);
		if (dbDriver == null)
			throw new Error("No database driver named (dbDriver=?)");
		setDbDriver(dbDriver);

		String dbURL = getOption("dbURL", null);
		if (dbURL == null)
			throw new Error("No database URL specified (dbURL=?)");
		setDbURL(dbURL);

		String dbUser = getOption("dbUser", null);
		setDbUser(dbUser);

		String dbPassword = getOption("dbPassword", null);
		setDbPassword(dbPassword);

		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
			throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		setUserTable(getOption("userTable", "User"));
		setUserColumn(getOption("userColumn", "user_name"));
		setPassColumn(getOption("passColumn", "user_passwd"));
		setSaltColumn(getOption("saltColumn", ""));
		setLastLoginColumn(getOption("lastLoginColumn", ""));
		setWhere(getOption("where", ""));

		if (getWhere() != null && getWhere().length() > 0)
			setWhere(" AND " + getWhere());
		else
			setWhere("");
	}

	protected synchronized Vector<TypedPrincipal> validateUser(String username, char password[]) throws LoginException {
		Connection connection = null;

		try {
			connection = (testConnection != null) ? testConnection
					: getConnection(getDbURL(), getDbUser(), getDbPassword());

			// Retrieve the stored hashed password from the database
			String[] passwordData = getPasswordFromDatabase(connection, username);
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
						String newSalt = PasswordUtils.SHA512_PREFIX + "rounds=" + PasswordUtils.SHA512_ROUNDS + "$"
								+ PasswordUtils.generateRandomSalt();
						String newHash = PasswordUtils.hashPassword(passwordBytes, newSalt, hashAlgorithm);
						updateStoredPassword(connection, username, newHash);
					}
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
			}

			// If password is valid, update the last login timestamp
			if (!lastLoginColumn.equals(""))
				updateLastLogin(connection, username);

			Vector<TypedPrincipal> p = new Vector<>();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			logger.debug("p: " + p.toString());
			return p;

		} catch (SQLException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					logger.error("Error closing connection", e);
				}
			}
		}
	}

	private String[] getPasswordFromDatabase(Connection connection, String username)
			throws SQLException, FailedLoginException, LoginException {
		String sql = new String();
		sql = "SELECT " + passColumn + (!saltColumn.equals("") ? ("," + saltColumn) : "") + " FROM " + userTable +
				" WHERE " + userColumn + "=?" + where;

		// Log the full SQL
		String fullSql = sql.replaceFirst("\\?", "'" + username + "'");
		logger.debug("Executing SQL: " + fullSql);

		try (PreparedStatement preparedStatment = connection.prepareStatement(sql)) {
			preparedStatment.setString(1, username);
			try (ResultSet resultSet = preparedStatment.executeQuery()) {
				if (!resultSet.next()) {
					throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
				}

				String password = resultSet.getString(1);
				String salt = (!saltColumn.equals("") ? resultSet.getString(2) : "");
				return new String[] { password, salt };
			} catch (SQLException e) {
				// Handle SQL exception
				e.printStackTrace();
				throw new LoginException("Error reading user database (" + e.getMessage() + ")");
			}
		}
	}

	private void updateStoredPassword(Connection connection, String username, String passwordHash) throws SQLException {
		logger.debug("Updating password for user: " + username);

		// SQL statement to update the password and salt columns
		String sql = "UPDATE " + userTable + " SET " + passColumn + " = ? WHERE " + userColumn + "= ?";

		try (PreparedStatement preparedStatment = connection.prepareStatement(sql)) {
			preparedStatment.setString(1, passwordHash);
			preparedStatment.setString(2, username);
			preparedStatment.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new SQLException("Error updating user database (" + e.getMessage() + ")");
		}
	}

	private void updateLastLogin(Connection connection, String username) throws SQLException {
		logger.debug("Updating last login for user: " + username);

		// SQL statement to update the last_login column
		String sql = getUpdateLastLoginSQL();

		try (PreparedStatement preparedStatment = connection.prepareStatement(sql)) {
			preparedStatment.setString(1, username);
			preparedStatment.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new SQLException("Error updating user database (" + e.getMessage() + ")");
		}
	}

	private String getUpdateLastLoginSQL() throws SQLException {
		String dbType = getDbType();
		String sql;

		logger.debug("DB Type: " + dbType);

		switch (dbType) {
			case "MySQL":
			case "PostgreSQL":
			case "SQLite":
				sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = CURRENT_TIMESTAMP WHERE " + userColumn
						+ " = ?";
				break;
			case "Oracle":
				sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = SYSDATE WHERE " + userColumn + " = ?";
				break;
			case "SQLServer":
				sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = GETDATE() WHERE " + userColumn + " = ?";
				break;
			case "h2":
				sql = "UPDATE " + userTable + " SET " + lastLoginColumn + " = CURRENT_TIMESTAMP() WHERE " + userColumn + " = ?";
			default:
				throw new UnsupportedOperationException("Unsupported DBMS: " + dbType);
		}

		logger.debug("SQL: " + sql);
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
		} else if (driverName.contains("h2")) {
			return "h2";
		} else {
			throw new UnsupportedOperationException("Unsupported DBMS: " + driverName);
		}
	}
}

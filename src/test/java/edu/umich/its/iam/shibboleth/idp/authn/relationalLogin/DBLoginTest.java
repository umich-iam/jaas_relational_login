package edu.umich.its.iam.shibboleth.idp.authn.relationalLogin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Method;
import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.login.LoginException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.junit.jupiter.api.Assertions;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)

public class DBLoginTest {

    private DBLogin dbLogin;
    private Connection testConnection;

    @BeforeEach
    public void setUp() throws SQLException {
        dbLogin = new DBLogin();

        // Create an in-memory H2 database connection for testing
        testConnection = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");

        // Set the test connection
        dbLogin.setTestConnection(testConnection);

        // Create a table and insert test data
        try (Statement stmt = testConnection.createStatement()) {
            stmt.execute("DROP TABLE IF EXISTS users");
            stmt.execute("CREATE TABLE users (username VARCHAR(255), password VARCHAR(255), salt VARCHAR(255), last_login TIMESTAMP, active BOOLEAN)");
            stmt.execute("INSERT INTO users (username, password, salt, last_login, active) VALUES ('testuser', 'password123', 'randomsalt', CURRENT_TIMESTAMP, TRUE)");
        }
    }

    private Map<String, Object> getDefaultOptions() {
        Map<String, Object> options = new HashMap<>();
        options.put("dbDriver", "DB_DRIVER_MYSQL"); // Required option
        options.put("dbURL", "jdbc:mysql://localhost:3306/testdb");
        options.put("dbUser", "testuser");
        options.put("dbPassword", "testpassword");
        options.put("userTable", "users");
        options.put("userColumn", "username");
        options.put("passColumn", "password");
        options.put("saltColumn", "salt");
        options.put("lastLoginColumn", "last_login");
        options.put("where", "active = TRUE");
        return options;
    }

    @Test
    public void testGetPasswordFromDatabase_WithSalt() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
        options.put("hashAlgorithm", "");

        dbLogin.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Call the method under test
        Object result = method.invoke(dbLogin, testConnection, "testuser");

        // Handle the result if it's an array
        String password;
        if (result instanceof String[]) {
            String[] resultArray = (String[]) result;
            password = resultArray.length > 0 ? resultArray[0] : null;
        } else {
            password = (String) result;
        }

        // Verify the results
        assertNotNull(password);
        assertEquals("password123", password);
    }

    // @Test
    // public void testGetPasswordFromDatabase_WithoutSalt() throws Exception {
    // }

    // @Test
    // public void testGetPasswordFromDatabase_WithEmptySalt() throws Exception {
    // }

    // @Test
    // public void testGetPasswordFromDatabase_WithValidUsername() throws Exception {
    // }

    // @Test
    // public void testGetPasswordFromDatabase_WithInvalidUsername() throws Exception {
    // }
    
    // @Test
    // public void testGetPasswordFromDatabase_WithDatabaseConnectionFailure() throws Exception {
    // }
    
    @Test
    public void testValidateUser_WithValidCredentials() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
        options.put("hashAlgorithm", "");

        dbLogin.initialize(null, null, null, options);

        char [] validPassword = "password123".toCharArray();

        // Call the method under test
        Vector<TypedPrincipal> principals = dbLogin.validateUser("testuser", validPassword);

        // Verify the results
        System.err.println(principals);
        assertNotNull(principals);
        assertFalse(principals.isEmpty());
        assertEquals("testuser", principals.get(0).getName());
    }


    @Test
    public void testValidateUser_WithInvalidCredentials() {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
    
        dbLogin.initialize(null, null, null, options);
        
        char[] invalidPassword = "invalidPassword".toCharArray();
    
        // Expect LoginException to be thrown
        Assertions.assertThrows(LoginException.class, () -> {
            dbLogin.validateUser("testuser", invalidPassword);
        });
    }

    @Test
    public void testValidateUser_WithEmptyCredentials() {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
    
        dbLogin.initialize(null, null, null, options);
        
        char[] emptyPassword = "".toCharArray();
    
        // Expect LoginException to be thrown
        Assertions.assertThrows(LoginException.class, () -> {
            dbLogin.validateUser("testuser", emptyPassword);
        });
    }

}
package com.robertogallea.shibboleth.idp.authn.relationalLogin;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.junit.jupiter.api.Assertions;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)

public class DBLoginTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ResultSet mockResultSet;

    @InjectMocks
    private DBLogin dbLoginInstance;

    @BeforeEach
    public void setUp() throws Exception {
        // Initialize mocks
        MockitoAnnotations.openMocks(this);

        // Mock the behavior of the ResultSet
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("hashedPassword123");
        when(mockResultSet.getString(2)).thenReturn("expectedSalt");

        // Mock the behavior of the PreparedStatement and Connection
        // Variable to capture the SQL query
        final String[] capturedQuery = new String[1];
        final String[] capturedUsername = new String[1];

        // Mock the behavior of the PreparedStatement and Connection
        when(mockConnection.prepareStatement(anyString())).thenAnswer(invocation -> {
            capturedQuery[0] = invocation.getArgument(0, String.class);
            return mockPreparedStatement;
        });

        doAnswer(invocation -> {
            capturedUsername[0] = invocation.getArgument(1, String.class);
            return null;
        }).when(mockPreparedStatement).setString(eq(1), anyString());

        when(mockPreparedStatement.executeQuery()).thenAnswer(invocation -> {
            // Capture the query from the PreparedStatement
            String query = capturedQuery[0];
            System.err.println("query: " + query);
            System.err.println("username: " + capturedUsername[0]);
            if ("testUsername".equals(capturedUsername[0])) {
                return mockResultSet;
            } else if ("validUsername".equals(capturedUsername[0])) {
                return mockResultSet;
            } else {
                // Simulate no results for invalid username
                ResultSet emptyResultSet = mock(ResultSet.class);
                when(emptyResultSet.next()).thenReturn(false);
                return emptyResultSet;
            }
        });

         // Mock the behavior of the Connection
         when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);

        // Initialize DBLogin with default options
        dbLoginInstance = new DBLogin();
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
        options.put("where", "active = 1");
        return options;
    }

    @Test
    public void testGetPasswordFromDatabase_WithSalt() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, mockConnection, "testUsername");

        // Print the contents of the result array
        System.err.println("result: " + Arrays.toString(result));

        // Add a check to ensure the result is not null
        Assertions.assertNotNull(result, "The result should not be null");

        String actualPassword = result[0];
        String actualSalt = result[1];

        // Verify the result
        Assertions.assertEquals("hashedPassword123", actualPassword, "The password should match the expected value");
        Assertions.assertEquals("expectedSalt", actualSalt, "The salt should match the expected value");

        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, "testUsername");
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString(1);
        verify(mockResultSet).getString(2);
    }

    @Test
    public void testGetPasswordFromDatabase_WithoutSalt() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
        options.remove("saltColumn"); // Remove the saltColumn

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, mockConnection, "testUsername");

        // Print the contents of the result array
        System.err.println("result: " + Arrays.toString(result));

        // Add a check to ensure the result is not null
        Assertions.assertNotNull(result, "The result should not be null");

        String actualPassword = result[0];

        // Verify the result
        Assertions.assertEquals("hashedPassword123", actualPassword, "The password should match the expected value");

        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, "testUsername");
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString(1);
    }

    @Test
    public void testGetPasswordFromDatabase_WithEmptySalt() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();
        options.put("saltColumn", ""); // Remove the saltColumn

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, mockConnection, "testUsername");

        // Print the contents of the result array
        System.err.println("result: " + Arrays.toString(result));

        // Add a check to ensure the result is not null
        Assertions.assertNotNull(result, "The result should not be null");

        String actualPassword = result[0];

        // Verify the result
        Assertions.assertEquals("hashedPassword123", actualPassword, "The password should match the expected value");

        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, "testUsername");
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString(1);
    }

    @Test
    public void testGetPasswordFromDatabase_WithValidUsername() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, mockConnection, "validUsername");

        // Print the contents of the result array
        System.err.println("result: " + Arrays.toString(result));

        // Add a check to ensure the result is not null
        Assertions.assertNotNull(result, "The result should not be null");

        String actualPassword = result[0];
        String actualSalt = result[1];

        // Verify the result
        Assertions.assertEquals("hashedPassword123", actualPassword, "The password should match the expected value");
        Assertions.assertEquals("expectedSalt", actualSalt, "The salt should match the expected value");

        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, "validUsername");
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString(1);
        verify(mockResultSet).getString(2);
    }

    @Test
    public void testGetPasswordFromDatabase_WithInvalidUsername() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Verify that the method throws an exception for an invalid username
        Assertions.assertThrows(FailedLoginException.class, () -> {
            try {
                method.invoke(dbLoginInstance, mockConnection, "invalidUsername");
            } catch (InvocationTargetException e) {
                // Unwrap the underlying exception
                if (e.getCause() instanceof FailedLoginException) {
                    throw (FailedLoginException) e.getCause();
                } else {
                    throw e;
                }
            }
        }, "An exception should be thrown for an invalid username");

        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, "invalidUsername");
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet, never()).next();
        verify(mockResultSet, never()).getString(1);
        verify(mockResultSet, never()).getString(2);
    }

    @Test
    public void testGetPasswordFromDatabase_WithDatabaseConnectionFailure() throws Exception {
        // Get default options and modify as needed
        Map<String, Object> options = getDefaultOptions();

        dbLoginInstance.initialize(null, null, null, options);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", Connection.class, String.class);
        method.setAccessible(true);

        // Simulate a database connection failure
        when(mockConnection.prepareStatement(anyString())).thenThrow(SQLException.class);
        Assertions.assertThrows(SQLException.class, () -> {
            try {
                method.invoke(dbLoginInstance, mockConnection, "testUsername");
            } catch (InvocationTargetException e) {
                // Unwrap the underlying exception
                if (e.getCause() instanceof SQLException) {
                    throw (SQLException) e.getCause();
                } else {
                    throw e;
                }
            }
        });
    }

    // @Test
    // public void testValidateUser_WithValidCredentials() throws LoginException, SQLException {
    //     // Mock the behavior of the DBLogin to return the mock Connection
    //     DBLogin dbLoginSpy = spy(dbLoginInstance);
    //     doReturn(mockConnection).when(dbLoginSpy).getConnection();

    //     // Get default options and modify as needed
    //     Map<String, Object> options = getDefaultOptions();
    //     dbLoginSpy.initialize(null, null, null, options);

    //     char[] validPassword = "validPassword".toCharArray();
    //     Vector<TypedPrincipal> result = dbLoginSpy.validateUser("validUsername", validPassword);
    //     Assertions.assertNotNull(result, "The user should be validated with valid credentials");
    //     Assertions.assertFalse(result.isEmpty(), "The result should not be empty for valid credentials");
    // }


    // @Test
    // public void testValidateUser_WithInvalidCredentials() {
    //     char[] invalidPassword = "invalidPassword".toCharArray();
    //     try {
    //         Vector<TypedPrincipal> result = dbLoginInstance.validateUser("validUsername", invalidPassword);
    //         Assertions.fail("The user should not be validated with invalid credentials");
    //     } catch (LoginException e) {
    //         // Expected exception
    //     }
    // }

    // @Test
    // public void testValidateUser_WithEmptyCredentials() {
    //     char[] emptyPassword = "".toCharArray();
    //     try {
    //         Vector<TypedPrincipal> result = dbLoginInstance.validateUser("", emptyPassword);
    //         Assertions.fail("The user should not be validated with empty credentials");
    //     } catch (LoginException e) {
    //         // Expected exception
    //     }
    // }

}
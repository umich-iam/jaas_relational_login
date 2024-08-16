package com.robertogallea.shibboleth.idp.authn.relationalLogin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class DBLoginTest {

    // Define constants at the top level
    private static final String USERNAME = "testUser";
    private static final String EXPECTED_PASSWORD = "hashedPassword123";
    private static final String EXPECTED_SALT = "randomSalt";

    private static final String DB_DRIVER_MYSQL = "com.mysql.cj.jdbc.Driver";
    private static final String DB_DRIVER_POSTGRESQL = "org.postgresql.Driver";

    private CallbackHandler callbackHandler;
    private DBLogin dbLoginInstance;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @BeforeEach
    public void setUp() throws Exception {
        callbackHandler = new SimpleCallbackHandler(USERNAME, EXPECTED_PASSWORD.toCharArray());

        // Initialize the mock objects
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
    }

    private void initializeDBLogin(String dbDriver) throws Exception {
        // Create a spy of DBLogin to mock the initialize method
        DBLogin dbLoginInstance = spy(new DBLogin());
        Subject subject = new Subject();
        Map<String, Object> sharedState = new HashMap<>();
        Map<String, Object> options = new HashMap<>();
        options.put("dbDriver", dbDriver);
        options.put("dbURL", "jdbc:example://localhost/testdb");

        dbLoginInstance.initialize(subject, callbackHandler, sharedState, options);

        // Use reflection to set the mock connection
        Field connectionField = DBLogin.class.getDeclaredField("connection");
        connectionField.setAccessible(true);
        connectionField.set(dbLoginInstance, mockConnection);
    }

    @Test
    public void testGetPasswordFromDatabase_WithSalt() throws Exception {
        initializeDBLogin(DB_DRIVER_MYSQL);

        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", String.class);
        method.setAccessible(true);
    
        // Mock the behavior of the ResultSet
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("password")).thenReturn(EXPECTED_PASSWORD);
        when(mockResultSet.getString("salt")).thenReturn(EXPECTED_SALT);

        // // Set the userColumn field to a non-null value
        // Field userTableField = DBLogin.class.getDeclaredField("userTable");
        // userTableField.setAccessible(true);
        // userTableField.set(dbLoginInstance, "passowrdTable");

        // // Set the userColumn field to a non-null value
        // Field userColumnField = DBLogin.class.getDeclaredField("userColumn");
        // userColumnField.setAccessible(true);
        // userColumnField.set(dbLoginInstance, "username");
    
        // // Set the passColumn field to a non-null value
        // Field passColumnField = DBLogin.class.getDeclaredField("passColumn");
        // passColumnField.setAccessible(true);
        // passColumnField.set(dbLoginInstance, "password");

        // Set the saltColumn field to a non-null value
        Field saltColumnField = DBLogin.class.getDeclaredField("saltColumn");
        saltColumnField.setAccessible(true);
        saltColumnField.set(dbLoginInstance, "salt");
    
        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, USERNAME);

        // Add a check to ensure the result is not null
        assertNotNull(result, "The result should not be null");

        String actualPassword = result[0];
        String actualSalt = result[1];
    
        // Verify the result
        assertEquals(EXPECTED_PASSWORD, actualPassword, "The password should match the expected value");
        assertEquals(EXPECTED_SALT, actualSalt, "The salt should match the expected value");
    
        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, USERNAME);
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString("password");
        verify(mockResultSet).getString("salt");
    }
    
    @Test
    public void testGetPasswordFromDatabase_WithoutSalt() throws Exception {
        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", String.class);
        method.setAccessible(true);
    
        // Mock the behavior of the ResultSet
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("password")).thenReturn(EXPECTED_PASSWORD);
        when(mockResultSet.getString("salt")).thenReturn(null); // Mock the salt column as null
    
        // Set the mock connection to the instance
        Field connectionField = DBLogin.class.getDeclaredField("connection");
        connectionField.setAccessible(true);
        connectionField.set(dbLoginInstance, mockConnection);
    
        // Set the saltColumn field to a non-null value
        Field saltColumnField = DBLogin.class.getDeclaredField("saltColumn");
        saltColumnField.setAccessible(true);
        saltColumnField.set(dbLoginInstance, "salt");
    
        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, USERNAME);
        String actualPassword = result[0];
        String actualSalt = result[1];
    
        // Verify the result
        assertEquals(EXPECTED_PASSWORD, actualPassword, "The password should match the expected value");
        assertNull(actualSalt, "The salt should be null");
    
        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, USERNAME);
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString("password");
        verify(mockResultSet).getString("salt");
    }
    
    @Test
    public void testGetPasswordFromDatabase_NoSaltColumn() throws Exception {
        // Use reflection to access the private method
        Method method = DBLogin.class.getDeclaredMethod("getPasswordFromDatabase", String.class);
        method.setAccessible(true);
    
        // Mock the behavior of the ResultSet
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("password")).thenReturn(EXPECTED_PASSWORD);
    
        // Set the mock connection to the instance
        Field connectionField = DBLogin.class.getDeclaredField("connection");
        connectionField.setAccessible(true);
        connectionField.set(dbLoginInstance, mockConnection);
    
        // Ensure the saltColumn field is not set (null)
        Field saltColumnField = DBLogin.class.getDeclaredField("saltColumn");
        saltColumnField.setAccessible(true);
        saltColumnField.set(dbLoginInstance, null);
    
        // Call the method under test using reflection
        String[] result = (String[]) method.invoke(dbLoginInstance, USERNAME);
        String actualPassword = result[0];
    
        // Verify the result
        assertEquals(EXPECTED_PASSWORD, actualPassword, "The password should match the expected value");
    
        // Verify interactions with the mock objects
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(1, USERNAME);
        verify(mockPreparedStatement).executeQuery();
        verify(mockResultSet).next();
        verify(mockResultSet).getString("password");
    }

    // @Test
    // public void testSuccessfulLogin() throws SQLException {
    // String username = "testUser";
    // String password = "testPassword";

    // when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
    // when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
    // when(mockResultSet.next()).thenReturn(true);
    // when(mockResultSet.getString("password")).thenReturn("hashedPassword");

    // boolean result = dbLogin.login(username, password);

    // assertTrue(result);
    // verify(mockPreparedStatement).setString(1, username);
    // verify(mockPreparedStatement).setString(2, password);
    // }

    // @Test
    // public void testFailedLogin() throws SQLException {
    // String username = "testUser";
    // String password = "wrongPassword";

    // when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
    // when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
    // when(mockResultSet.next()).thenReturn(false);

    // boolean result = dbLogin.login(username, password);

    // assertFalse(result);
    // verify(mockPreparedStatement).setString(1, username);
    // verify(mockPreparedStatement).setString(2, password);
    // }

    // @Test
    // public void testSQLException() throws SQLException {
    // String username = "testUser";
    // String password = "testPassword";

    // when(mockConnection.prepareStatement(anyString())).thenThrow(new
    // SQLException());

    // assertThrows(SQLException.class, () -> {
    // dbLogin.login(username, password);
    // });
    // }
}
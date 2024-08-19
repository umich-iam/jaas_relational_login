package com.robertogallea.shibboleth.idp.authn.relationalLogin;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

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
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);

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
}
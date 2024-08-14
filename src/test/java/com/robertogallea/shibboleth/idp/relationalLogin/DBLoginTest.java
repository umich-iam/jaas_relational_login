package com.robertogallea.shibboleth.idp.relationalLogin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class DBLoginTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ResultSet mockResultSet;

    @InjectMocks
    private DBLogin dbLogin;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testSuccessfulLogin() throws SQLException {
        String username = "testUser";
        String password = "testPassword";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("password")).thenReturn("hashedPassword");

        boolean result = dbLogin.login(username, password);

        assertTrue(result);
        verify(mockPreparedStatement).setString(1, username);
        verify(mockPreparedStatement).setString(2, password);
    }

    @Test
    public void testFailedLogin() throws SQLException {
        String username = "testUser";
        String password = "wrongPassword";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        boolean result = dbLogin.login(username, password);

        assertFalse(result);
        verify(mockPreparedStatement).setString(1, username);
        verify(mockPreparedStatement).setString(2, password);
    }

    @Test
    public void testSQLException() throws SQLException {
        String username = "testUser";
        String password = "testPassword";

        when(mockConnection.prepareStatement(anyString())).thenThrow(new SQLException());

        assertThrows(SQLException.class, () -> {
            dbLogin.login(username, password);
        });
    }
}
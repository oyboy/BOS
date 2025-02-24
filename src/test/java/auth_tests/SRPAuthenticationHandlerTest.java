package auth_tests;

import auth.SRPAuthenticationHandler;
import client.users.SRPUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import server.JDBCService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SRPAuthenticationHandlerTest {
    private SRPAuthenticationHandler srpHandler;
    private JDBCService jdbcServiceMock;
    private BufferedReader inMock;
    private BufferedWriter outMock;

    @BeforeEach
    void setUp() {
        srpHandler = new SRPAuthenticationHandler();
        jdbcServiceMock = Mockito.mock(JDBCService.class);
        inMock = Mockito.mock(BufferedReader.class);
        outMock = Mockito.mock(BufferedWriter.class);
    }

    @Test
    void testRegisterUser() throws Exception {
        String login = "User1";
        String password = "qwerty";

        srpHandler.registerUser(login, password);

        verify(jdbcServiceMock).dropTable();
        verify(jdbcServiceMock).createUserTable(any(SRPUser.class));
        verify(jdbcServiceMock).insertUser(any(SRPUser.class));
        //verify(jdbcServiceMock).close();
    }
    @Test
    void testHandleClientAuthentication() throws IOException {
        srpHandler.handleClientAuthentication(inMock, outMock);
        srpHandler.handleServerAuthentication(inMock, outMock);

        verify(outMock).write(anyString());
        verify(outMock).write(eq("M1\n"));
        verify(outMock, atLeastOnce()).flush();
    }
    @Test
    void testHandleClientAuthenticationThrowsWhenBIsZero() throws IOException {
        when(inMock.readLine())
                .thenReturn("salt")
                .thenReturn("0");

        assertThrows(IOException.class, () -> {
            srpHandler.handleClientAuthentication(inMock, outMock);
        });
    }
}

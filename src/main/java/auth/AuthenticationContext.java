package auth;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

public class AuthenticationContext {
    private AuthenticationHandler handler;

    public AuthenticationContext(AuthenticationHandler handler) {
        this.handler = handler;
    }

    public void setHandler(AuthenticationHandler handler) {
        this.handler = handler;
    }

    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        handler.handleClientAuthentication(in, out);
    }

    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        handler.handleServerAuthentication(in, out);
    }

    public void registerUser(String username, String password) throws Exception {
        handler.registerUser(username, password);
    }
}

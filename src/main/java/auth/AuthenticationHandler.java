package auth;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

public interface AuthenticationHandler {
    void registerUser(String username, String password) throws Exception;
    // Метод для обработки аутентификации на стороне клиента
    void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException;
    // На стороне сервера
    void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException;
}
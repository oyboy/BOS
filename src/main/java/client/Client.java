package client;

import auth.*;

import java.io.*;
import java.net.*;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 8082;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            System.out.println("Подключение к серверу установлено.");

            AuthenticationContext context = new AuthenticationContext(new SRPAuthenticationHandler());
            try{
                context.registerUser("user", "1234");
            } catch (Exception e) {
                System.out.println("Ошибка регистрации: " + e.getMessage());
            }
            context.handleClientAuthentication(in, out);
        } catch (IOException e) {
            System.out.println("Client error: " + e.getMessage());
        }
    }
}
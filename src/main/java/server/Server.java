package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    private static final int port = 8082;

    public static void main(String[] args) {
        try(ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            while(true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected");

                new ClientHandler(clientSocket).start();
            }
        } catch (IOException e) {
            System.out.println("Server exception: " + e);
        }
    }
}
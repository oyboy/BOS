package server;

import auth.*;

import java.io.*;
import java.net.Socket;

public class ClientHandler extends Thread {
    private final Socket clientSocket;
    private BufferedReader in;
    private BufferedWriter out;
    private static final int TIMEOUT = 15000; //15s

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            clientSocket.setSoTimeout(TIMEOUT);

            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

            AuthenticationContext context = new AuthenticationContext(new FiatShamir());
            context.handleServerAuthentication(in, out);
        } catch (IOException e) {
            System.out.println("Error i/o stream: " + e.getMessage());
        }
    }
}
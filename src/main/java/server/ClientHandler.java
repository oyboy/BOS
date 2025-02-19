package server;

import auth.AuthenticationContext;
import auth.SRPAuthenticationHandler;

import java.io.*;
import java.net.Socket;

public class ClientHandler extends Thread {
    private final Socket clientSocket;
    private BufferedReader in;
    private BufferedWriter out;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

            AuthenticationContext context = new AuthenticationContext(new SRPAuthenticationHandler());
            context.handleServerAuthentication(in, out);

        } catch (IOException e) {
            System.out.println("Error i/o stream: " + e.getMessage());
        } finally {
            closeResources();
        }
    }
    private void closeResources() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException e) {
            System.out.println("Error closing resources: " + e.getMessage());
        }
    }
}
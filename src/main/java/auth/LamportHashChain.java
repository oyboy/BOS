package auth;

import client.users.LamportUser;
import server.HashUtil;
import server.JDBCService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

public class LamportHashChain implements AuthenticationHandler {
    private final int N = 90000;
    private final JDBCService jdbc = new JDBCService();
    private final String serverName = "localhost:8082";
    @Override
    public void registerUser(String username, String password) throws Exception {
        jdbc.dropTable();
        jdbc.createUserTable(new LamportUser());

        String P = password + " | " + serverName;
        int n = 0;
        while (n < N) {
            P = HashUtil.generateHash(P);
            System.out.println("Current p: " + P);
            n++;
        }
        jdbc.insertUser(username, P);
    }

    @Override
    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        String username = "User1";
        String password = "qwerty";
        String P = password + " | " + serverName;
        String[] chain = HashUtil.generateHashChain(P, N);

        System.out.println("Отправка логина");
        out.write(username + "\n");
        out.flush();

        int A = Integer.parseInt(in.readLine());
        System.out.println("Получено A: " + A);

        System.out.println("Отправка на сервер: " + chain[N-A-1]);
        out.write(chain[N-A-1] + "\n");
        out.flush();

        String result;
        if ((result = in.readLine()) != null) System.out.println(result);
        else System.out.println("Авторизация провалена");
    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        String username = in.readLine();
        LamportUser lamportUser = jdbc.getLamportUserFromDB(username);
        if (lamportUser == null) throw new IOException("User not found");

        out.write(lamportUser.getA() + "\n");
        out.flush();

        String hash = in.readLine();
        System.out.println("Got hash: " + hash);
        String expected = lamportUser.getHash();
        System.out.println("Expected: " + expected);
        String actual = HashUtil.generateHash(hash);
        System.out.println("Actual: " + actual);
        if (!expected.equals(actual)) throw new IOException("Auth error: hashes don't match");

        jdbc.updateUser(username, hash, lamportUser.getA() + 1);

        out.write("Авторизация успешна \n");
        out.flush();

        jdbc.close();
    }
}
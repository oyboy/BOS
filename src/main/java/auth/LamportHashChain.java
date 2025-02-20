package auth;

import client.users.LamportUser;
import server.HashUtil;
import server.JDBCService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

public class LamportHashChain implements AuthenticationHandler {
    private final int N = 90000;
    private int A = 0;

    @Override
    public void registerUser(String username, String password) throws Exception {
        JDBCService jdbc = new JDBCService();
        jdbc.dropTable();
        jdbc.createUserTable(new LamportUser());

        String P = password + " | " + "localhost:8081";
        int n = 0;
        while (n < N - A) {
            P = HashUtil.generateHash(P);
            n++;
        }
        A = 1;
        jdbc.insertUser(username, P);
        jdbc.close();
    }

    @Override
    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        String username = "User1";
        String password = "qwerty";
        String P = password + " | " + "localhost:8081";
        String[] chain = HashUtil.generateHashChain(P, N);

        System.out.println("Отправка предпоследнего хеша");
        out.write(username + "\n");
        out.write(chain[N-1] + "\n");
        out.flush();

    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        JDBCService jdbc = new JDBCService();

        String username = in.readLine();
        String hash = in.readLine();

        LamportUser lamportUser = jdbc.getLamportUserFromDB(username);
        if (lamportUser == null) throw new IOException("User not found");

        String expected = lamportUser.getHash();
        String actual = HashUtil.generateHash(hash);
        if (!expected.equals(actual)) throw new IOException("Hash does not match");

        jdbc.updateUser(username, hash);
        jdbc.close();

        System.out.println("Авторизация успешна??");
    }
}
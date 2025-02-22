package auth;

import client.users.LamportUser;
import server.HashUtil;
import server.JDBCService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

import java.util.List;
import java.util.Objects;

public class LamportHashChain implements AuthenticationHandler {
    private final int N = 90000;
    private final JDBCService jdbc = new JDBCService();
    private final String serverName = "localhost:8082";

    /*public LamportHashChain() {
        jdbc.createHistoryTable();
    }*/

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
        LamportUser user = new LamportUser(username, P);
        jdbc.insertUser(user);
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
        //A -= 1;
        System.out.println("Получено A: " + A);

        System.out.println("Отправка на сервер: " + chain[N-A-1]);
        out.write(chain[N-A-1] + "\n");
        out.flush();

        String result = in.readLine();
        if (result.startsWith("Рассинхронизация")) {
            int newA = Integer.parseInt(result.split(": ")[1]);

            out.write(chain[N - newA - 1] + "\n");
            out.flush();

            result = in.readLine();
            System.out.println(Objects.requireNonNullElse(result, "Авторизация провалена"));
        } else System.out.println(result);
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
        String actual = HashUtil.generateHash(hash);
        System.out.println("Actual: " + actual);
        String expected = lamportUser.getHash();
        System.out.println("Expected: " + expected);

        if (expected.equals(actual)) {
            jdbc.updateUser(username, hash, lamportUser.getA() + 1);
            out.write("Авторизация успешна \n");
            out.flush();
        } else {
            if (checkPreviousHashes(username, hash)) {
                out.write("Рассинхронизация. Текущее значение A: " + lamportUser.getA() + "\n");
                out.flush();

                String newHash = in.readLine();
                System.out.println("Получен новый хеш от клиента: " + newHash);
                String newExpected = lamportUser.getHash();
                String newActual = HashUtil.generateHash(newHash);
                if (newExpected.equals(newActual)) {
                    int newA = lamportUser.getA() + 1;

                    jdbc.updateUser(username, newHash, newA);

                    out.write("Авторизация успешна \n");
                    out.flush();
                }
            } else {
                out.write("Ошибка аутентификации: хеши не совпадают");
                out.flush();
                throw new IOException("Auth error: hashes don't match");
            }
        }
    }
    /*Проверка рассинхранизации счётчика*/
    private boolean checkPreviousHashes(String login, String hash) {
        List<String> previousHashes = jdbc.getPreviousHashes(login);
        for (String prevHash : previousHashes) {
            if (prevHash.equals(hash)) return true;
        }
        return false;
    }
}
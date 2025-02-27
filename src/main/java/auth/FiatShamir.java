package auth;

import client.users.FiatUser;
import server.JDBCService;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class FiatShamir implements AuthenticationHandler {
    private final int k = 7;
    private final int t = 16;
    private final SecureRandom rnd = new SecureRandom();
    private final BigInteger n;

    public FiatShamir() {
        this.n = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
                "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
                "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
                "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
                "FD5138FE8376435B9FC61D2FC0EB06E3",
            16);
    }

    @Override
    public void registerUser(String username, String password) throws Exception {
        JDBCService jdbc = new JDBCService();
        if (jdbc.userExists(username)) return;

        FiatUser user = new FiatUser();
        jdbc.dropTable();
        jdbc.createUserTable(user);

        BigInteger[] secrets = new BigInteger[k];
        BigInteger[] verifs = new BigInteger[k];
        for (int i = 0; i < k; i++) {
            secrets[i] = new BigInteger(n.bitLength(), rnd).mod(n);
            verifs[i] = secrets[i].modPow(BigInteger.TWO, n);
        }
        user.setLogin(username);
        user.setVerifs(verifs);

        jdbc.insertUser(user);
        saveSecretsToFile(secrets);
    }

    @Override
    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        System.out.println("n: " + n);
        BigInteger[] secrets = loadSecretsFromFile();

        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter login: ");
        String login = scanner.nextLine();
        out.write(login + "\n");
        out.flush();

        for (int round = 0; round < t; round++){
            BigInteger r = new BigInteger(n.bitLength(), rnd).mod(n);
            BigInteger x = r.modPow(BigInteger.TWO, n);

            out.write(x + "\n");
            out.flush();

            int[] b = Arrays.stream(in.readLine().split(","))
                    .mapToInt(Integer::parseInt)
                    .toArray();
            /*Вычисление y*/
            BigInteger y = r;
            for (int i = 0; i < k; i++) {
                if (b[i] == 1) y = y.multiply(secrets[i]).mod(n);
            }
            out.write(y + "\n");
            out.flush();

            /*Проверка результата*/
            String result = in.readLine();
            //System.out.println("Result: " + result);
            if (!result.equals("Success")) {
                throw new IOException("Authentication failed");
            }
        }
        System.out.println("Success authentication");
    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        System.out.println("n: " + n);
        JDBCService jdbc = new JDBCService();
        String login = in.readLine();
        System.out.println("Получен запрос на авторизацию: " + login);
        FiatUser user = jdbc.getFiatUserFromDB(login);

        if (user == null) {
            in.close();
            out.close();
            throw new IOException("User does not exist");
        }

        BigInteger[] verifs = user.getVerifs();

        for (int round = 0; round < t; round++){
            System.out.println("---------------------------------");
            System.out.println("Шаг: " + (round+1));
            BigInteger x = new BigInteger(in.readLine());
            System.out.println("x: " + x);
            /*Отправка битового вектора*/
            int[] b = new int[k];
            for (int i = 0; i < k; i++) {
                b[i] = rnd.nextInt(2);
            }
            out.write(Arrays.stream(b)
                    .mapToObj(Integer::toString)
                    .reduce((a1, a2) -> a1 + "," + a2)
                    .orElse(""));
            out.newLine();
            out.flush();

            /*Проверка условия */
            BigInteger y = new BigInteger(in.readLine());
            System.out.println("y: " + y);
            BigInteger z = x;
            for (int i = 0; i < k; i++) {
                if (b[i] == 1) z = z.multiply(verifs[i]).mod(n);
            }
            System.out.println("z: " + z);
            BigInteger ySquared = y.modPow(BigInteger.TWO, n);
            System.out.println("y^2 mod n: " + ySquared);
            if (z.equals(ySquared)) {
                out.write("Success\n");
                out.flush();
            }
            else {
                out.write("Fail\n");
                out.flush();
                break;
            }
        }
    }
    private void saveSecretsToFile(BigInteger[] secrets) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("client_secrets.txt"))) {
            for (BigInteger secret : secrets) {
                writer.write(secret.toString());
                writer.newLine();
            }
        }
    }
    private BigInteger[] loadSecretsFromFile() throws IOException {
        BigInteger[] secrets = new BigInteger[k];
        try (BufferedReader reader = new BufferedReader(new FileReader("client_secrets.txt"))) {
            for (int i = 0; i < k; i++) {
                String line = reader.readLine();
                secrets[i] = new BigInteger(line);
            }
        }
        return secrets;
    }
}

package auth;

import client.users.FiatUser;
import server.JDBCService;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class FiatShamir implements AuthenticationHandler {
    private final int k = 5;
    private final int t = 16;
    private final SecureRandom rnd = new SecureRandom();
    private final BigInteger n;

    public FiatShamir() {
        BigInteger p = BigInteger.probablePrime(512, rnd);
        BigInteger q = BigInteger.probablePrime(512, rnd);
        n = p.multiply(q);
    }

    @Override
    public void registerUser(String username, String password) throws Exception {
        JDBCService jdbc = new JDBCService();
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
        BigInteger[] secrets = loadSecretsFromFile();

        String login = "User1";
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
            System.out.println("Получен вектор: " + b);
            printVector(b);
            /*Вычисление y*/
            BigInteger y = r;
            for (int i = 0; i < k; i++) {
                if (b[i] == 1) y = y.multiply(secrets[i]).mod(n);
            }
            out.write(y + "\n");
            out.flush();

            /*Проверка результата*/
            String result = in.readLine();
            System.out.println("Result: " + result);
            if (!result.equals("OK")) {
                throw new IOException("Authentication failed");
            }
        }
    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        JDBCService jdbc = new JDBCService();
        String login = in.readLine();
        System.out.println("Получен запрос на авторизацию: " + login);
        FiatUser user = jdbc.getFiatUserFromDB(login);

        BigInteger[] verifs = user.getVerifs();

        for (int round = 0; round < t; round++){
            System.out.println("Шаг: " + (round+1));
            BigInteger x = new BigInteger(in.readLine());
            System.out.println("Получено x: " + x);
            /*Отправка битового вектора*/
            int[] b = new int[k];
            for (int i = 0; i < k; i++) {
                b[i] = rnd.nextInt(2);
            }
            System.out.println("Отправка вектора: " + b);
            printVector(b);
            out.write(Arrays.stream(b)
                    .mapToObj(Integer::toString)
                    .reduce((a1, a2) -> a1 + "," + a2)
                    .orElse(""));
            out.newLine();
            out.flush();

            /*Проверка условия */
            BigInteger y = new BigInteger(in.readLine());
            System.out.println("Значение y для сверки: " + y);
            BigInteger z = y.pow(2);
            for (int i = 0; i < k; i++) {
                if (b[i] == 1) z = z.multiply(verifs[i]).mod(n);
            }
            System.out.println("Вычисленное z: " + z);
            if (z.equals(x.mod(n)) || z.equals(x.mod(n).negate()) && !z.equals(BigInteger.ZERO)) {
                out.write("Success\n");
                out.flush();
            } else {
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
    private void printVector(int[] b){
        for (int i = 0; i < b.length; i++) {
            System.out.print(b[i] + " ");
        }
        System.out.println();
    }
}

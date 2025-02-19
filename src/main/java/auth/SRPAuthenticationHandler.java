package auth;

import server.HashUtil;
import server.JDBCService;
import server.User;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SRPAuthenticationHandler implements AuthenticationHandler {
    private static final BigInteger N = new BigInteger(
            "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
                    "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
                    "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
                    "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
                    "FD5138FE8376435B9FC61D2FC0EB06E3",
            16
    );
    private static final BigInteger g = new BigInteger("2");
    private static final SecureRandom rnd = new SecureRandom();

    @Override
    public void registerUser(String login, String password) throws Exception {
        JDBCService jdbc = new JDBCService();
        jdbc.createUserTable();

        String s = HashUtil.generateRandomSalt();
        BigInteger x = HashUtil.computeX(s, login, password);
        BigInteger v = g.modPow(x, N);

        jdbc.insertUser(login, s, v.toString(16));
        jdbc.close();
    }

    @Override
    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        BigInteger a = new BigInteger(N.bitLength(), rnd);
        System.out.println("a = " + a);

        BigInteger A = a.modPow(g, N);
        System.out.println("A = " + A);

        BigInteger k = new BigInteger(
                HashUtil.generateHash(N.toString(16) + g.toString(16)), 16
        );
        System.out.println("k = " + k);

        String login = "User1";
        String password = "qwertyy";

        System.out.println("Передача l и A");
        out.write(login + "\n"); //l
        out.write(A.toString(16) + "\n"); //A
        out.flush();

        System.out.println("Чтение s и B");
        String salt = in.readLine();

        BigInteger B = new BigInteger(in.readLine(), 16);
        if (B.equals("0")) throw new IOException("Client authentication failed: B is 0");
        System.out.println("B: " + B);

        System.out.println("Вычисление x, u");
        BigInteger x = HashUtil.computeX(salt, login, password);
        System.out.println("x: " + x);

        BigInteger u = new BigInteger(HashUtil.generateHash(A.toString(16) + B), 16);
        System.out.println("u: " + u);

        BigInteger Sc = B.subtract(g.modPow(x, N).multiply(k)).modPow(a.add(u.multiply(x)), N);
        System.out.println("Sc = " + Sc);

        String M1 = HashUtil.generateHash(A.toString(16) + B + Sc);
        System.out.println("Передача M1");
        out.write(M1 + "\n");
        out.flush();
    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        String login = in.readLine();
        System.out.println("Login: " + login);
        BigInteger A = new BigInteger(in.readLine(), 16);
        System.out.println("A: " + A);
        if (A.equals("0")) throw new IOException("Server authentication failed: A is 0");


        JDBCService jdbc = new JDBCService();

        BigInteger b = new BigInteger(N.bitLength(), rnd);
        System.out.println("b: " + b);

        User user = jdbc.getUserFromDB(login);
        if (user == null) throw new IOException("Server authentication failed: user not found");

        System.out.println("Генерация k, v, B, u");
        BigInteger k = new BigInteger(
                HashUtil.generateHash(N.toString(16) + g.toString(16)),
                16
        );
        System.out.println("k: " + k);

        BigInteger v = new BigInteger(user.getVerificator(), 16);
        System.out.println("v: " + v);

        BigInteger B = v.multiply(k).add(g.modPow(b, N));
        System.out.println("B: " + B);

        BigInteger u = new BigInteger(HashUtil.generateHash(A.toString(16) + B), 16);
        System.out.println("u: " + u);

        System.out.println("Передача s, B");
        System.out.println("salt = " + user.getSalt());
        out.write(user.getSalt() + "\n"); //s
        out.write(B.toString(16) + "\n"); //B
        out.flush();

        BigInteger Ss = A.multiply(v.modPow(u, N)).modPow(b, N);
        System.out.println("Ss: " + Ss);

        String M1 = in.readLine();
        String M2 = HashUtil.generateHash(A.toString(16) + M1 + Ss);
        System.out.println("M1: " + M1);
        System.out.println("M2: " + M2);
    }
}
package auth;

import server.MessageHandler;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman implements AuthenticationHandler {
    private static final SecureRandom RND = new SecureRandom();
    private static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger g = new BigInteger("5");

    @Override
    public void registerUser(String username, String password) throws Exception {}

    @Override
    public void handleClientAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        BigInteger a = new BigInteger(512, RND);
        BigInteger A = g.modPow(a, P);

        out.write(A+"\n");
        out.flush();

        BigInteger B = new BigInteger(in.readLine());
        BigInteger S = B.modPow(a, P);

        MessageHandler messageHandler = new MessageHandler(in, out, S);
        messageHandler.startReading();
        messageHandler.startWriting();
        System.out.println("Запущены потоки чтения/записи");
    }

    @Override
    public void handleServerAuthentication(BufferedReader in, BufferedWriter out) throws IOException {
        BigInteger b = new BigInteger(512, RND);
        BigInteger B = g.modPow(b, P);

        BigInteger A = new BigInteger(in.readLine());

        out.write(B+"\n");
        out.flush();

        BigInteger S = A.modPow(b, P);

        MessageHandler messageHandler = new MessageHandler(in, out, S);
        messageHandler.startReading();
        messageHandler.startWriting();
        System.out.println("Запущены потоки чтения/записи");
    }
}
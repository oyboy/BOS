package server;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class MessageHandler {
    private final BigInteger secretKey;
    private BufferedReader in;
    private BufferedWriter out;
    private volatile boolean running = true;
    private Thread readThread;
    private Thread writeThread;

    public MessageHandler(BufferedReader in, BufferedWriter out, BigInteger secretKey) {
        this.in = in;
        this.out = out;
        this.secretKey = secretKey;
    }

    public void startReading() {
        readThread = new Thread(() -> {
            try {
                while (running) {
                    String encryptedMessage = in.readLine();
                    if (encryptedMessage == null) {
                        System.out.println("Соединение закрыто клиентом.");
                        break;
                    }
                    System.out.println("Получено зашифрованное сообщение: " + encryptedMessage);
                    String decryptedMessage = decryptMessage(encryptedMessage, secretKey);
                    if (decryptedMessage != null) {
                        System.out.println("Расшифрованное сообщение: " + decryptedMessage);
                    }
                }
            } catch (IOException e) {
                System.err.println("Ошибка при чтении сообщения: " + e.getMessage());
            } finally {
                stop();
            }
        });
        readThread.start();
    }

    public void startWriting() {
        writeThread = new Thread(() -> {
            try (BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in))) {
                while (running) {
                    String message = consoleInput.readLine();
                    if (message == null || message.trim().isEmpty()) {
                        continue;
                    }
                    String encryptedMessage = encryptMessage(message, secretKey);
                    if (encryptedMessage != null) {
                        out.write(encryptedMessage + "\n");
                        out.flush();
                        System.out.println("Отправлено сообщение : "+ encryptedMessage);
                    }
                }
            } catch (IOException e) {
                System.err.println("Ошибка при отправке сообщения: " + e.getMessage());
            } finally {
                stop();
            }
        });
        writeThread.start();
    }

    public boolean isRunning() {
        return running;
    }

    public void stop() {
        running = false;
        try {
            if (in != null) in.close();
            if (out != null) out.close();
        } catch (IOException e) {
            System.out.println("Ошибка при закрытии ресурсов: " + e.getMessage());
        }
    }
    private String encryptMessage(String message, BigInteger key) {
        if (message == null || message.trim().isEmpty()) {
            System.err.println("Message is null or empty.");
            return null;
        }
        try {
            byte[] keyBytes = key.toByteArray();
            byte[] aesKey = new byte[16];
            System.arraycopy(keyBytes, 0, aesKey, 0, Math.min(keyBytes.length, 16));

            Key secretKey = new SecretKeySpec(aesKey, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
            return null;
        }
    }

    private String decryptMessage(String encryptedMessage, BigInteger key) {
        if (encryptedMessage == null || encryptedMessage.trim().isEmpty()) {
            System.err.println("Encrypted message is null or empty.");
            return null;
        }

        try {
            if (!encryptedMessage.matches("[A-Za-z0-9+/=]+")) {
                System.err.println("Invalid Base64 characters in message: " + encryptedMessage);
                return null;
            }
            byte[] keyBytes = key.toByteArray();
            byte[] aesKey = new byte[16];
            System.arraycopy(keyBytes, 0, aesKey, 0, Math.min(keyBytes.length, 16));

            Key secretKey = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            System.err.println("Base64 decoding error: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            return null;
        }
    }
}
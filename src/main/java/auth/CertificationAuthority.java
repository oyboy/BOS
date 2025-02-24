package auth;

import java.math.BigInteger;
import java.security.SecureRandom;

public class CertificationAuthority {
    private static CertificationAuthority instance;
    private final BigInteger n;

    private CertificationAuthority() {
        SecureRandom rnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(256, rnd);
        BigInteger q = BigInteger.probablePrime(256, rnd);
        this.n = p.multiply(q);
    }

    public static synchronized CertificationAuthority getInstance() {
        if (instance == null) {
            synchronized (CertificationAuthority.class) {
                if (instance == null) {
                    instance = new CertificationAuthority();
                }
            }
        }
        return instance;
    }

    public BigInteger getN() {
        return n;
    }
}
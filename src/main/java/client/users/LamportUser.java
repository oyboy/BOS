package client.users;

public class LamportUser extends User {
    private String login;
    private String hash;
    private int A;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public int getA() {
        return A;
    }

    public void setA(int a) {
        A = a;
    }
}

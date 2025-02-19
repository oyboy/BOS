package server;

public class User {
    private long id;
    private String login;
    private String salt;
    private String verificator;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getVerificator() {
        return verificator;
    }

    public void setVerificator(String verificator) {
        this.verificator = verificator;
    }
}

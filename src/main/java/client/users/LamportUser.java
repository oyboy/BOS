package client.users;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public class LamportUser implements User {
    private String login;
    private String hash;
    private int A;

    public LamportUser() {}
    public LamportUser(String login, String hash) {
        this.login = login;
        this.hash = hash;
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

    @Override
    public String getLogin() {
        return login;
    }
    @Override
    public String getInsertQuery() {
        return "INSERT INTO user (login, hash) VALUES (?, ?)";
    }

    @Override
    public void setPreparedStatementParameters(PreparedStatement preparedStatement) throws SQLException {
        preparedStatement.setString(1, login);
        preparedStatement.setString(2, hash);
    }

    @Override
    public String getCreateTableQuery() {
        return "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) NOT NULL, " +
                "hash VARCHAR(255) NOT NULL," +
                "A INT NOT NULL DEFAULT 0)";
    }
}

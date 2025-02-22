package client.users;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SRPUser implements User {
    private String login;
    private String salt;
    private String verificator;

    public SRPUser() {}

    public SRPUser(String login, String salt, String verificator) {
        this.login = login;
        this.salt = salt;
        this.verificator = verificator;
    }

    public String getSalt() {
        return salt;
    }

    public String getVerificator() {
        return verificator;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public void setVerificator(String verificator) {
        this.verificator = verificator;
    }

    @Override
    public String getLogin() {
        return login;
    }

    @Override
    public String getInsertQuery() {
        return "INSERT INTO user (login, salt, verificator) VALUES (?, ?, ?)";
    }

    @Override
    public void setPreparedStatementParameters(PreparedStatement preparedStatement) throws SQLException {
        preparedStatement.setString(1, login);
        preparedStatement.setString(2, salt);
        preparedStatement.setString(3, verificator);
    }

    @Override
    public String getCreateTableQuery() {
        return "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) UNIQUE NOT NULL, " +
                "salt VARCHAR(255) NOT NULL, " +
                "verificator TEXT NOT NULL)";
    }
}

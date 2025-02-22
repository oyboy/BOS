package client.users;

import java.math.BigInteger;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class FiatUser implements User {
    private String login;
    private BigInteger[] verifs;

    public FiatUser() {}
    public FiatUser(String login, BigInteger[] verifs) {
        this.login = login;
        this.verifs = verifs;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public BigInteger[] getVerifs() {
        return verifs;
    }

    public void setVerifs(BigInteger[] verifs) {
        this.verifs = verifs;
    }

    @Override
    public String getInsertQuery() {
        return "INSERT INTO user (login, verifs) VALUES (?, ?)";
    }

    @Override
    public String getCreateTableQuery() {
        return "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) NOT NULL, " +
                "verifs TEXT NOT NULL)";
    }

    @Override
    public void setPreparedStatementParameters(PreparedStatement preparedStatement) throws SQLException {
        preparedStatement.setString(1, login);
        preparedStatement.setString(2, bigIntegerArrayToString(verifs));
    }

    private String bigIntegerArrayToString(BigInteger[] arr) {
        if (arr == null || arr.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arr.length; i++) {
            sb.append(arr[i].toString());
            if (i < arr.length - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }
}

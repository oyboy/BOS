package client.users;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public interface User {
    String getLogin();
    String getInsertQuery();
    String getCreateTableQuery();
    void setPreparedStatementParameters(PreparedStatement preparedStatement) throws SQLException;
}

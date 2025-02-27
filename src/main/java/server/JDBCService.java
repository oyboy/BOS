package server;

import client.users.FiatUser;
import client.users.LamportUser;
import client.users.SRPUser;
import client.users.User;

import java.math.BigInteger;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class JDBCService {
    private final Connection connection;

    public JDBCService() {
        String url = "jdbc:mysql://localhost:3306/bosdb";
        String user = "root";
        String passwd = "root";
        try {
            connection = DriverManager.getConnection(url, user, passwd);
        } catch (SQLException e) {
            throw new RuntimeException("Ошибка подключения к базе данных: " + e.getMessage(), e);
        }
    }
    public void dropTable() {
        String sql = "DROP TABLE IF EXISTS user";
        try{
            connection.createStatement().executeUpdate(sql);
        } catch (SQLException e) {
            System.out.println("Can't drop user table: " + e.getMessage());
        }
    }
    public void createHistoryTable(){
        String query = "CREATE TABLE IF NOT EXISTS lamport_history ("+
                "id INT AUTO_INCREMENT PRIMARY KEY," +
                "login VARCHAR(255) NOT NULL," +
                "hash VARCHAR(255) NOT NULL," +
                "A INT NOT NULL," +
                "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(query);
            System.out.println("Создана таблица истории счётчикоа");
        } catch (SQLException e) {
            System.out.println("Ошибка при создании таблицы: " + e.getMessage());
        }
    }

    public void createUserTable(User user) {
        String createTableQuery = user.getCreateTableQuery();

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(createTableQuery);
            System.out.println("Таблица пользователей создана или уже существует");
        } catch (SQLException e) {
            System.out.println("Ошибка при создании таблицы: " + e.getMessage());
        }
    }

    // Проверка существования пользователя по логину
    public boolean userExists(String login) {
        String checkUserQuery = "SELECT COUNT(*) FROM user WHERE login = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(checkUserQuery)) {
            preparedStatement.setString(1, login);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            System.out.println("Ошибка при проверке пользователя: " + e.getMessage());
        }
        return false;
    }

    public void insertUser(User user) {
        if (userExists(user.getLogin())) {
            System.out.println("Пользователь с логином " + user.getLogin() + " уже существует.");
            return;
        }
        String insertUserQuery = user.getInsertQuery();
        try (PreparedStatement preparedStatement = connection.prepareStatement(insertUserQuery)) {
            user.setPreparedStatementParameters(preparedStatement);
            preparedStatement.executeUpdate();
            System.out.println("Пользователь успешно добавлен.");
        } catch (SQLException e) {
            System.out.println("Ошибка при добавлении пользователя: " + e.getMessage());
        }
    }


    public void updateUser(String login, String hash, int A) {
        if (!userExists(login)) {
            System.out.println("Пользователь не найден");
            return;
        }
        String updateUserQuery = "UPDATE user SET hash = ?, A = ? WHERE login = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(updateUserQuery)) {
            preparedStatement.setString(1, hash);
            preparedStatement.setInt(2, A);
            preparedStatement.setString(3, login);

            int rowsUpdated = preparedStatement.executeUpdate();
            if (rowsUpdated > 0) {
                System.out.println("An existing user was updated successfully!");
            }
        } catch (SQLException e) {
            System.out.println("Update user failed: " + e.getMessage());
        }
        /*Сохранение в таблицу истории*/
        String insertHistoryQuery = "INSERT INTO lamport_history (login, hash, A) VALUES (?, ?, ?)";
        try (PreparedStatement preparedStatement = connection.prepareStatement(insertHistoryQuery)) {
            preparedStatement.setString(1, login);
            preparedStatement.setString(2, hash);
            preparedStatement.setInt(3, A);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            System.out.println("Insert history failed: " + e.getMessage());
        }
    }
    public List<String> getPreviousHashes(String login) {
        List<String> previousHashes = new ArrayList<>();

        String selectHistoryQuery = "SELECT hash FROM lamport_history WHERE login = ? ORDER BY timestamp DESC LIMIT 5";
        try (PreparedStatement preparedStatement = connection.prepareStatement(selectHistoryQuery)) {
            preparedStatement.setString(1, login);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    String previousHash = resultSet.getString("hash");
                    previousHashes.add(previousHash);
                }
            }
        } catch (SQLException e) {
            System.out.println("Select history failed: " + e.getMessage());
        }
        return previousHashes;
    }

    public SRPUser getSRPUserFromDB(String login) {
        String selectSql = "SELECT * FROM user WHERE login = ?";

        try (PreparedStatement statement = connection.prepareStatement(selectSql)){
            statement.setString(1, login);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                SRPUser SRPUser = new SRPUser();
                //SRPUser.setId(resultSet.getLong("id"));
                SRPUser.setLogin(resultSet.getString("login"));
                SRPUser.setSalt(resultSet.getString("salt"));
                SRPUser.setVerificator(resultSet.getString("verificator"));

                return SRPUser;
            }
        } catch (SQLException e) {
            System.out.println("Ошибка при получении пользователей: " + e.getMessage());
        }
        return null;
    }
    public LamportUser getLamportUserFromDB(String login) {
        String selectSql = "SELECT * FROM user WHERE login = ?";

        try (PreparedStatement statement = connection.prepareStatement(selectSql)){
            statement.setString(1, login);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                LamportUser lamportUser = new LamportUser();
               // lamportUser.setId(resultSet.getLong("id"));
                lamportUser.setLogin(resultSet.getString("login"));
                lamportUser.setHash(resultSet.getString("hash"));
                lamportUser.setA(resultSet.getInt("A"));

                return lamportUser;
            }
        } catch (SQLException e) {
            System.out.println("Ошибка при получении пользователей: " + e.getMessage());
        }
        return null;
    }
    private BigInteger[] stringToBigIntegerArray(String str) {
        if (str == null || str.isEmpty()) {
            return new BigInteger[0];
        }
        String[] strArr = str.split(",");
        BigInteger[] arr = new BigInteger[strArr.length];
        for (int i = 0; i < strArr.length; i++) {
            arr[i] = new BigInteger(strArr[i].trim());
        }
        return arr;
    }
    public FiatUser getFiatUserFromDB(String login) {
        String selectSql = "SELECT * FROM user WHERE login = ?";

        try (PreparedStatement statement = connection.prepareStatement(selectSql)) {
            statement.setString(1, login);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                String loginFromDB = resultSet.getString("login");
                String verifsString = resultSet.getString("verifs");
                BigInteger[] verifs = stringToBigIntegerArray(verifsString);

                return new FiatUser(loginFromDB, verifs);
            }
        } catch (SQLException e) {
            System.out.println("Ошибка при получении FiatUser: " + e.getMessage());
            return null;
        }
        return null;
    }


    public void close() {
        if (connection != null) {
            try {
                connection.close();
                System.out.println("Соединение с базой данных закрыто.");
            } catch (SQLException e) {
                System.out.println("Ошибка при закрытии соединения: " + e.getMessage());
            }
        }
    }
}
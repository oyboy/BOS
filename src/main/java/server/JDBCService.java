package server;

import client.users.LamportUser;
import client.users.SRPUser;
import client.users.User;

import java.sql.*;

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

    public void createUserTable(User user) {
        String createTableQuery = null;
        if (user instanceof SRPUser) createTableQuery = "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) UNIQUE NOT NULL, " +
                "salt VARCHAR(255) NOT NULL, " +
                "verificator TEXT NOT NULL)";
        else if (user instanceof LamportUser) createTableQuery = "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) NOT NULL, " +
                "hash VARCHAR(255) NOT NULL," +
                "A INT NOT NULL DEFAULT 1)";

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

    public void insertUser(String login, String salt, String verificator) {
        if (userExists(login)) {
            System.out.println("Пользователь с логином " + login + " уже существует.");
            return;
        }

        String insertUserQuery = "INSERT INTO user (login, salt, verificator) VALUES (?, ?, ?)";
        try (PreparedStatement preparedStatement = connection.prepareStatement(insertUserQuery)) {
            preparedStatement.setString(1, login);
            preparedStatement.setString(2, salt);
            preparedStatement.setString(3, verificator);
            preparedStatement.executeUpdate();
            System.out.println("Пользователь успешно добавлен.");
        } catch (SQLException e) {
            System.out.println("Ошибка при добавлении пользователя: " + e.getMessage());
        }
    }
    public void insertUser(String login, String hash) {
        if (userExists(login)) {
            System.out.println("Пользователь с логином " + login + " уже существует.");
            return;
        }

        String insertUserQuery = "INSERT INTO user (login, hash) VALUES (?, ?)";
        try (PreparedStatement preparedStatement = connection.prepareStatement(insertUserQuery)) {
            preparedStatement.setString(1, login);
            preparedStatement.setString(2, hash);
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
    }

    public SRPUser getSRPUserFromDB(String login) {
        String selectSql = "SELECT * FROM user WHERE login = ?";

        try (PreparedStatement statement = connection.prepareStatement(selectSql)){
            statement.setString(1, login);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                SRPUser SRPUser = new SRPUser();
                SRPUser.setId(resultSet.getLong("id"));
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
                lamportUser.setId(resultSet.getLong("id"));
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
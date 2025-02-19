package server;

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

    public void createUserTable() {
        String createTableQuery = "CREATE TABLE IF NOT EXISTS user (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "login VARCHAR(255) UNIQUE NOT NULL, " +
                "salt VARCHAR(255) NOT NULL, " +
                "verificator TEXT NOT NULL)";

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(createTableQuery);
            System.out.println("Таблица пользователей создана или уже существует.");
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

    public User getUserFromDB(String login) {
        String selectSql = "SELECT * FROM user WHERE login = ?";

        try (PreparedStatement statement = connection.prepareStatement(selectSql)){
            statement.setString(1, login);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getLong("id"));
                user.setLogin(resultSet.getString("login"));
                user.setSalt(resultSet.getString("salt"));
                user.setVerificator(resultSet.getString("verificator"));

                return user;
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
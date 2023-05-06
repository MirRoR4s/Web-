package com.atguigu.api.statement;

import java.sql.*;
import java.util.Scanner;

public class StatementQuery1 {

    public static void main(String[] args) throws ClassNotFoundException, SQLException {

        Scanner scanner = new Scanner(System.in);

        System.out.println("输入账号");
        String account = scanner.nextLine();

        System.out.println("输入密码");
        String password = scanner.nextLine();


        Class.forName("com.mysql.cj.jdbc.Driver");

        Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/atguigu", "root", "root");


        String sql = "select * from t_user where account = '" + account + "' and password = '" + password + "' ;";

        Statement statement = connection.createStatement();

        ResultSet resultSet = statement.executeQuery(sql);

        while(resultSet.next()){
            System.out.println(resultSet.getString("nickname"));
            System.out.println(resultSet.getInt("id"));
        }

        resultSet.close();
        statement.close();
        connection.close();


    }
}

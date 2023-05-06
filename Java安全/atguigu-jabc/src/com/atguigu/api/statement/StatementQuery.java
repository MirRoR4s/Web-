package com.atguigu.api.statement;

import com.mysql.cj.jdbc.Driver;

import java.sql.*;

public class StatementQuery {
    /**
     * TODO:
     * DriverManager
     * Connection
     * Statement
     * ResultSet
     * @param args
     */

    public static void main(String[] args) throws SQLException {

        //1. 注册驱动
         DriverManager.registerDriver(new Driver());


        //2. 获取连接

        Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/atguigu","root","root");


        //3. 创建 statement

        Statement statement = connection.createStatement();




        //4. 发送sql语句，并且获取返回结果

        String sql = "select * from t_user";

        ResultSet resultSet = statement.executeQuery(sql);


        //5. 进行结果集解析

        while(resultSet.next()){

            int id = resultSet.getInt("id");

            System.out.println(id);


        }


    }
}

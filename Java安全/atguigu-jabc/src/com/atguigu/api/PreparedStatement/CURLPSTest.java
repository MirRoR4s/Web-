package com.atguigu.api.PreparedStatement;
import com.mysql.cj.jdbc.Driver;
import org.junit.Test;
import java.sql.*;

public class CURLPSTest {
    @Test
    public void testInsert() throws ClassNotFoundException, SQLException {

        Class.forName("com.mysql.cj.jdbc.Driver");

        Connection connection = DriverManager.getConnection("jdbc:mysql:///atguigu", "root", "root");


        String sql = "insert into t_user(account,password,nickname) values (?,?,?);";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);

        //占位符赋值
        preparedStatement.setString(1, "test");
        preparedStatement.setString(2, "test");
        preparedStatement.setString(3, "测试");

        //发送SQL语句
        int rows = preparedStatement.executeUpdate();

        int i = preparedStatement.executeUpdate();

        if(i > 0){
            System.out.println("插入成功");
        }


    }
    @Test
    public void testDelete() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.cj.jdbc.Driver");

        Connection connection = DriverManager.getConnection("jdbc:mysql:///atguigu?user=root&password=root");

        String sql = "delete from t_user where id=?";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);

        preparedStatement.setObject(1,3);

        int i = preparedStatement.executeUpdate();

        if(i > 0){
            System.out.println("删除成功");
        }


    }
    @Test
    public void testUpdate() throws ClassNotFoundException, SQLException {

        Class.forName("com.mysql.cj.jdbc.Driver");

        Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/atguigu", "root", "root");

        String sql = "update  t_user set nickname=? where id =?";

        PreparedStatement preparedStatement = connection.prepareStatement(sql);

        preparedStatement.setObject(1,"一切都会过去");
        preparedStatement.setObject(2,1);

        int i = preparedStatement.executeUpdate();

        if(i > 0){
            System.out.println("更新成功");
        }


    }
    @Test
    public void testSelect() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.cj.jdbc.Driver");

        Connection v = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/atguigu", "root", "root");

        String sql = "select * from t_user where id = ?";

        PreparedStatement preparedStatement = v.prepareStatement(sql);

        preparedStatement.setObject(1,1);

        ResultSet resultSet = preparedStatement.executeQuery();

        if(resultSet.next()){
            System.out.println("查询成功");
        }


    }
}

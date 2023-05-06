package com.atguigu.api.druid;

import com.alibaba.druid.pool.DruidDataSource;
import org.junit.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ConcurrentModificationException;

public class TestDruidHard {

    @Test
    public void druidHard() throws SQLException {

        DruidDataSource druidDataSource = new DruidDataSource();

        druidDataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        druidDataSource.setUsername("root");
        druidDataSource.setPassword("root");
        druidDataSource.setUrl("jdbc:mysql:///atguigu");


        Connection connection = druidDataSource.getConnection();

        connection.close();




    }

}

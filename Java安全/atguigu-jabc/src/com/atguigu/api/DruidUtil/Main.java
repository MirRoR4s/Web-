package com.atguigu.api.DruidUtil;

import java.sql.Connection;
import java.sql.SQLException;

public class Main {
    public static void main(String[] args) throws SQLException {

        JDBCToolsVersion1 jdbcToolsVersion1 = new JDBCToolsVersion1();

        Connection connection = JDBCToolsVersion1.getConnection();

        JDBCToolsVersion1.free(connection);




    }
}

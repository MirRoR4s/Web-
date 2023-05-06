package com.atguigu.api.druid;


import com.alibaba.druid.pool.DruidDataSourceFactory;
import org.junit.Test;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


public class TestDruidSoft {

    @Test
    public void druidSoft() throws Exception {

        Properties properties = new Properties();
        InputStream ips = TestDruidSoft.class.getClassLoader().getResourceAsStream("druid.properties");
        properties.load(ips);
        DataSource dataSource = DruidDataSourceFactory.createDataSource(properties);



    }

}

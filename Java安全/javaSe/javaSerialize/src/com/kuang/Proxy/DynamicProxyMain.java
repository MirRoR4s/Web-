package com.kuang.Proxy;

import sun.rmi.runtime.Log;

import java.lang.reflect.Proxy;

public class DynamicProxyMain {
    public static void main(String args[]){
        // 创建中介类实例
        LogHandler logHandler = new LogHandler(new Vendor());

        // 设置该变量可以保存动态代理类，默认名称$Proxy0.class
        System.getProperties().put("sun.misc.ProxyGenerator.saveGeneratedFiles", "true");

        Sell sell = (Sell) (Proxy.newProxyInstance(Sell.class.getClassLoader(), new Class[]{Sell.class}, logHandler));
        sell.sell();
        sell.ad();


    }
}

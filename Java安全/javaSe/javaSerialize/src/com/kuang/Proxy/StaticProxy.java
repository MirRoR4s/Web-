package com.kuang.Proxy;

public class StaticProxy {
    public static void main(String[] args){
        Vendor vendor = new Vendor();


        Sell sell = new Shop(vendor);
        sell.ad();
        sell.sell();


        
    }
}

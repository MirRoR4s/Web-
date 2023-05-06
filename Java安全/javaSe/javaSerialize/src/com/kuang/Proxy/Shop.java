package com.kuang.Proxy;

public class Shop implements Sell {

    private final Sell sell;

    public Shop(Sell sell){
        this.sell = sell;

    }
    public void sell(){
        System.out.println("代理类Shop，处理sell");
        sell.sell();

    }
    public void ad(){
        System.out.println("代理类Shop，处理ad");
        sell.ad();
    }

}

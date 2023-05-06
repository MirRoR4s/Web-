package com.kuang.Proxy;

public class Vendor implements Sell{
    @Override
    public void sell(){
        System.out.println("shop sell goods");

    }
    @Override
    public void ad(){
        System.out.println("Shop advert goods");

    }

}

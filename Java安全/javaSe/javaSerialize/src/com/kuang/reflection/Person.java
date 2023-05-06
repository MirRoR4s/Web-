package com.kuang.reflection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Person implements Serializable {

    private String name;
    private int age;

    public Person(){

    }
    // 构造函数
    public Person(String name, int age){
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString(){
        return "Person{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
    private void readObject(ObjectInputStream ois) throws IOException,ClassNotFoundException{
        ois.defaultReadObject();
        System.out.println("调用的是我写的！");
        Runtime.getRuntime().exec("calc");


    }
}
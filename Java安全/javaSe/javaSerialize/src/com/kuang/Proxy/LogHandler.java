package com.kuang.Proxy;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Date;


public class LogHandler implements InvocationHandler {
    Object target;
    public LogHandler(Object target){
        this.target = target;
    }
    public Object invoke(Object proxy,Method method,Object[] args) throws Throwable{

        before();
        Object result  = method.invoke(target,args); // 调用 target 的method方法
        after();
        return result;
    }
    private void before(){
        System.out.println(String.format("log start time [%s]",new Date()));

    }
    private void after(){
      System.out.println(String.format("log end time [%s]",new Date()));
    }



}

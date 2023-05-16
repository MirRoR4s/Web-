###### tags: `Java 反序列化`
[TOC]
# Java 反序列化之 CC7

## 前言

CC7 的链子也是和 CC5 类似，后半条链子也是 **LazyMap.get()** 的这条链子。

## 环境搭建
- JDK8u65
- CommonCollections 3.2.1


## CC7 分析

### 流程图

![](https://i.imgur.com/PnTYE1Q.png)

后半条链和 CC1 是一样的，前半条链子需要我们自己重新写一遍。如果是逆向分析的话，还是有点难度的，所以还是直接看 yso 官方的链子。

![](https://i.imgur.com/TN8OBuI.png)

接下来就跟着 yso 的流程图正向分析一遍链子。
> 注意现在我们是从 LazyMap.get() 着手，注意传到这里的时候 get() 方法的参数。

### 具体分析

假设现在是走到 LayMap.get() 方法，然后根据 yso 的调用链，现在链子的上一步是 AbstractMap.equals() 方法。

> 如果你在这里寻找相关调用，idea 会告诉你结果太多是否要导出，所以能挖掘出这个漏洞的人真的很有耐心。

### 1.java.util.AbstractMap.equals()

![](https://i.imgur.com/gWSAHkp.png)

上图 469 行的 m.get(key) 语句调用了 get() 方法。所以这里 m 应该是一个 LazyMap 类对象，而 m 变量是传给 equals 方法的参数 Object O，这是我们可控的。所以紧接着去看看上一步的方法
>记住，LazyMap的 get 方法随便传一个参数即可，因为我们可以通过 ChainedTransformer.transform() 转化，转化所需的相关参数值是在 LazyMap 的构造函数中定义的，所以我们只需要关心如何定义 LazyMap 就好，而不是去关注传给 LazyMap.get() 方法的参数是什么。

### 2. org.apache.commons.collections.map.AbstractMapDecorator.equals()

续说上文，由于 AbstractMapDecorator.equals() 调用了 AbstractMap.equals()，所以我们来看看这个 AbstractMapDecorator.equals() 。

>不要诧异为什么是 AbstractMapDecorator.equals() 调用了 AbstractMap.equals()，因为 AbstractMap 是 AbstractMapDecorator 的实现类，所以当你调用 AbstractMapDecorator.equals()，自然会转到其实现类的 equals() 方法上。


以下是该类 `equals()` 方法的定义

![](https://i.imgur.com/Sn6BsWY.png)

根据上一步我们知道这个 object 应该是一个 LazyMap 类对象，同时 map 应该是 AbstractMap 类对象。map 是什么？跟踪一下发现 map 是这个类的受保护的一个成员属性（transient？）


![](https://i.imgur.com/Ob8eGw4.png)

我们可在该类的构造函数中设置 map 变量的值：

![](https://i.imgur.com/ccddwqV.png)

根据链子，调用了 AbstractMapDecorator.equals() 方法的是 HashTable.reconstitutionPut() 方法，所以接下来就跟上去看看。

### 3. reconstitutionPut()

![](https://i.imgur.com/XePawnc.png)

上图 1221 行调用了 e.key.equals(key) 方法，这是漏洞的第三步。显然这个 `e.key` 需要是一个 AbstractMapDecorator 类对象，参数 key 需要是一个 LazyMap 类对象。

e.key 来自于传给这个方法的 Entry 数组 tab，参数 key 来自于传给这个方法的 key。
根据链子，是HashTable.readObject() 方法调用了 reconstitutionPut() ，所以我们继续跟上去。


### 4. java.util.Hashtable.readObject()




**readObject()**

![](https://i.imgur.com/BPBVVuj.png)

在上图 1195 行 循环调用了 `reconstitutionPut()` 方法，根据上一步的分析我们知道，这里传入的 key 需要是一个 LazyMap 类对象，table 是一个 Entry 类型的数组，同时必须要含有一个以 AbstractMapDecorator 为键的 entry，这样才可以完成漏洞链。

> 后面分析才知道这里应该是一个以 LazyMap 为键的 entry，只是因为 LazyMap 没有 equals 方法才会调用到其父类 AbstractMapDecorator 的 equals 方法

table 来自于那里呢？查看一下就会发现 table 是 HashTable 类的私有的成员属性

可惜 HashTable 的多个构造函数中没有能直接设置 table 的值的，并且在 readObject() 方法（1184 行）中重新定义了一次 table：

![](https://i.imgur.com/u2Q5WY6.png)

也就是说在反序列化的时候 table 是一个空的 Entry 数组，但我们要求 table 必须要含有一个以 AbstractMapDecorator 类对象为键的 entry，这时候我们该怎么办？

这就是这条链子的巧妙之处，解题的关键在于 `reconstitutionPut` 方法中可以构造 table：（tab 是 参数名，对应着 table）

![](https://i.imgur.com/nTUGZNP.png)

前面提到，我们是循环地调用 ReconstitutionPut() 方法，当我们第一次调用该方法的时候传入的 table 是空的，所以不能执行 1221 行的链子，但是会在 1228 行给 table 添加一个元素，这一行的参数 key 和 value 就是我们传给 ReconstitutionPut() 方法的 key 和 value。 key 显然是一个 LazyMap 类对象，value 可以随意赋值。

所以到这我们就有想法了，只调用一次 ReconstitutionPut() 方法会由于 table 为空导致无法执行到链子的 e.key.equals() 方法，所以我们需要执行两次 ReconstitutionPut() 方法，这表示 1173 行的 elements 元素值应该为2，所以 HashTable 类对象应该要有两个 entry。这样我们就可以调用两次 ReconstitutionPut() 方法，并且在第二次调用的时候由于 e=tab\[index\] 不为空，所以可以进入链子的语句里面去。但是这里还有一个小细节（1221 行），那就是由于 && 运算的短路特性，我们必须要让 `(e.hash == hash)` 为真才可以执行 `e.key.equals(key)`。同时由于这个 if 判断为真会抛出异常，所以我们又不能让 `e.key.equals(key)` 为真，否则两个同时为真就直接抛出异常了。那现在我们就要寻找哈希碰撞了，也就是本身不同，但是哈希码相同。
直接给出答案：

`"yy".hashCode() == "zZ".hashCode()`

你可能会感到疑惑，现在不是求 key 的 hashCode，而前面说 key 需要为 LazyMap 类对象吗？为什么给出了两个字符串的 hashCode 呢？
答：因为在调用 LazyMap.hashCode() 的时候实际上是在求这个 LazyMap 类对象的 map 成员变量的 hashCode() 方法（由于 LazyMap 没有 hashCode() 方法，所以会调用其父类 AbstractMapDecorator 的 hashCode() 方法）

![](https://i.imgur.com/7fAkuyR.png)

由于 AbstractMapDecorator 是个抽象类，所以会自动调用到其实现类 AbstractMap 的 hashCode() 方法

![](https://i.imgur.com/y3uEVCb.png)

根据 LazyMap 的构造我们知道其成员属性 map 其实是一个 HashMap 类对象，所以上图的 entrySet().iterator() 实际上会调用 HashMap 类的 entrySet().iterator()并最终在 507 行调用了 HashMap 的 hashCode() 方法：

![](https://i.imgur.com/vrmxkS1.png)

从上图我们可以知道 HashMap.hashCode() 和 key 以及 value 相关。 在 value 相同的情况下，若传入 `yy` 和 `zZ` 作为 key，那么计算出的两个 hashCode 是一样的。

经过以上细致的分析，现在我们可以开始着手书写 EXP 了。

回到我们的 ReconstitutionPut() 方法中，现在 hash 是当前轮的 key 对应的 hashCode，e.key 是上一轮的 key 对应的 hashCode。

我们现在按照以上分析构造两个 LazyMap 对象比如 LazyMap1、LazyMap2 并把它们加入 HashTable 类对象中。

**注意：在调用完 HashTable.put() 之后，还需要在 Lazymap2 中 remove() 掉 yy**

这是因为 Hashtable.put() 实际上也会调用到 equals() 方法：
当调用完 equals() 方法后，LazyMap2 的 key 中就会增加一个 yy 键：

这就不能满足 hash 碰撞了，构造序列化链的时候是满足的，但是构造完成之后就不满足了，那么经过对方服务器反序列化也不能满足 hash 碰撞了，也就不会执行系统命令了，所以就在构造完序列化链之后手动删除这多出来的一组键值对。












## 参考链接

[ysoCC7](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections7.java)

[芜风师傅](https://drun1baby.github.io/2022/06/29/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8708-CC7%E9%93%BE/)
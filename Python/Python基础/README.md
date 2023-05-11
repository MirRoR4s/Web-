# Python 基础

> 入门参看-[菜鸟教程](https://www.runoob.com/python/python-tutorial.html)



## 前言

一定要对 python 面向对象方面多加了解，因为 CTF 的 SSTI、沙箱逃逸等都要用到 python 一些类的方法和属性。



## Python 内置类属性

> 可以先看看[这篇](https://segmentfault.com/a/1190000042311727)



```python
__init__ 是 类的构造函数或初始化方法，当创建了类的实例时就会调用该方法。
__dict__：类的属性（包含一个字典，由类的数据属性组成）
__name__：类名
__module__：类定义所在的模块。如果类位于一个导入模块 mymod 中，那么 className.__module__ 等于 mymod
__bases__：类的所有父类构成元素（包含了一个由所有父类组成的元组）
__del__：析构函数，在对象销毁时被调用
```

![image-20230505115422656](picture/image-20230505115422656.png)

### \_\_mro\_\_

要稍加学习一些的是 python 的 [mro](https://docs.python.org/3/library/stdtypes.html?highlight=mro#class.__mro__) 方法及属性：

![image-20230505115455522](picture/image-20230505115455522.png)

官方文档说 \_\_mro\_\_ 属性是一个类的元组，是什么类呢？是在方法解析期间寻找基类时所考虑的类。这样看来有些抽象，我在[此处](https://cloud.tencent.com/developer/article/1741952)找到了一个比较好的回答。看完这篇文章后对 mro 方法是做什么的、结果是咋样的会有一个清晰的了解。

- 如果说要想明白 mro 是如何做的呢？可以参看[知乎](https://www.zhihu.com/tardis/zm/art/416584599?source_id=1003)的这篇文章。

### \_\_class\_\_

类的实例在获取 `__class__` 属性时会返回该实例对应的类。

```python
>>> ''.__class__ # '' 对应字符串类
<class 'str'>
```

### \_\_globals\_\_

参看[官方文档](https://docs.python.org/3/reference/datamodel.html?highlight=__globals__)

## Python 函数

### vars()

- https://www.runoob.com/python/python-func-vars.html

![image-20230508162827640](picture/image-20230508162827640.png)

这个函数会以字典的形式返回对象的属性和属性值，若是一个类对象，那么**类对象的函数也算作属性**。

```python
class Runoob:
    a = 1
    def test(self):
        print(1)

print(vars(Runoob))
#{'__module__': '__main__', 'a': 1, 'test': <function Runoob.test at 0x000001DF676D68C0>, '__dict__': <attribute '__dict__' of 'Runoob' objects>, '__weakref__': <attribute '__weakref__' of 'Runoob' objects>, '__doc__': None}
```



## Python 语言特性

### Python 中的 [:-1] 和 [::-1]

- 参考[菜鸟教程](https://www.runoob.com/note/51257)

```python
b = a[i:j]   # 表示复制 a[i] 到 a[j-1]，以生成新的 list 对象

a = [0,1,2,3,4,5,6,7,8,9]
b = a[1:3]   # [1,2]

# 当 i 缺省时，默认为 0，即 a[:3] 相当于 a[0:3]
# 当 j 缺省时，默认为 len(alist), 即 a[1:] 相当于 a[1:10]
# 当 i,j 都缺省时，a[:] 就相当于完整复制一份 a

b = a[i:j:s]    # 表示：i,j与上面的一样，但 s 表示步进，缺省为 1.
# 所以 a[i:j:1] 相当于 a[i:j]

# 当 s<0 时，i 缺省时，默认为 -1. j 缺省时，默认为 -len(a)-1
# 所以 a[::-1] 相当于 a[-1:-len(a)-1:-1]，也就是从最后一个元素到第一个元素复制一遍，即倒序。

```

- 当 s 大于零时，i 缺省，默认为 0，j 缺省时，默认为 len(a)

所以 a[::2] == a[0,len(a),2]








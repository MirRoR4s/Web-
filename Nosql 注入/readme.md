# Nosql 从零到一

- 参考链接

## 什么是 Nosql

NoSQL 即 Not Only SQL，意即 “不仅仅是SQL”。NoSQL 是一项全新的数据库革命性运动，早期就有人提出，发展至 2009 年趋势越发高涨。NoSQL 的拥护者们提倡运用非关系型的数据存储，相对于铺天盖地的关系型数据库运用，这一概念无疑是一种全新的思维的注入。

## 什么是 MongoDB

MongoDB 是当前最流行的 NoSQL 数据库产品之一，由 C++ 语言编写，是一个基于分布式文件存储的数据库。旨在为 WEB 应用提供可扩展的高性能数据存储解决方案。

MongoDB 将数据存储为一个文档，数据结构由键值（key=>value）对组成。MongoDB 文档类似于 JSON 对象。字段值可以包含其他文档，数组及文档数组。

```sql
{
    "_id" : ObjectId("60fa854cf8aaaf4f21049148"),
    "name" : "whoami",
    "description" : "the admin user",
    "age" : 19,
    "status" : "A",
    "groups" : [
        "admins",
        "users"
    ]
}
```



## MongoDB 基础概念解析

不管我们学习什么数据库都应该学习其中的基础概念，在 MongoDB 中基本的概念有文档、集合、数据库，如下表所示：

| SQL 概念    | MongoDB 概念 | 说明                                      |
| ----------- | ------------ | ----------------------------------------- |
| database    | database     | 数据库                                    |
| table       | collection   | 数据库表/集合                             |
| row         | document     | 数据记录行/文档                           |
| column      | field        | 数据字段/域                               |
| index       | index        | 索引                                      |
| table joins |              | 表连接，MongoDB 不支持                    |
| primary key | primary key  | 主键，MongoDB 自动将 `_id` 字段设置为主键 |

下表列出了关系型数据库 RDBMS 与 MongoDB 之间对应的术语：

| RDBMS  | MongoDB                           |
| ------ | --------------------------------- |
| 数据库 | 数据库                            |
| 表格   | 集合                              |
| 行     | 文档                              |
| 列     | 字段                              |
| 表联合 | 嵌入文档                          |
| 主键   | 主键（MongoDB 提供了 key 为 _id） |

也就是说：

- MongoDB 中的集合对应关系型数据库中的表。

- MongoDB 中的文档对应关系型数据库中的行。
- MongoDB 中的字段对应关系型数据库中的列。



### 数据库（Database）

一个 MongoDB 中可以建立多个数据库。MongoDB 的单个实例可以容纳多个独立的数据库，每一个都有自己的集合和权限，不同的数据库也放置在不同的文件中。

使用 `show dbs` 命令可以显示所有数据库的列表：

```sql
$ ./mongo
MongoDB shell version: 3.0.6
connecting to: test
> show dbs
admin   0.078GB
config  0.078GB
local   0.078GB
>
```

执行 `db` 命令可以显示当前数据库对象或集合：

```sql
$ ./mongo
MongoDB shell version: 3.0.6
connecting to: test
> db
test
>
```

### 文档（document）

文档是一组键值（key-value）对，类似于 RDBMS 关系型数据库中的一行。MongoDB 的文档不需要设置相同的字段，并且相同的字段不需要相同的数据类型，这与关系型数据库有很大的区别，也是 MongoDB 非常突出的特点。

> 不是很理解不需要设置相同的字段这句话？仔细想想应该是说在关系型数据库中，一个表的多行它们的字段是相同的，但是在 MongoDB 中，多个文档它们的字段可以不同。
>
> 

一个简单的文档例子如下：

```sql
{"name":"whoami", "age":19}
```

### 集合（Collection）

集合就是 MongoDB 文档组，类似于 RDBMS 关系数据库管理系统中的表格。集合存在于数据库中，集合没有固定的结构，这意味着集合可以插入不同格式和类型的数据。

比如，我们可以将以下不同数据结构的文档插入到集合中：

```sql
{"name":"whoami"}
{"name":"bunny", "age":19}
{"name":"bob", "age":20, "groups":["admins","users"]}
```

当插入一个文档时，集合就会被自动创建。

如果我们要查看已有集合，可以使用 `show collections` 或 `show tables` 命令：

```
> show collections
all_users
> show tables
all_users
>
```


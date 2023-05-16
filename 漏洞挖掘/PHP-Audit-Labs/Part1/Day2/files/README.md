## Day 2 - Twig

题目叫做 Twig，代码如下：

![1](1.png)

**漏洞解析** ：

这一关题目实际上用的是PHP的一个模板引擎 [Twig](https://twig.symfony.com/) ，本题考察 XSS (跨站脚本攻击) 漏洞。虽然题目代码分别用了 **escape** 和 **filter_var** 两个过滤方法，但是还是可以被攻击者绕过。在上图 **第8行** 中，程序使用 [Twig](https://twig.symfony.com/) 模板引擎定义的 **escape** 过滤器来过滤 link ，而实际上这里的 **escape** 过滤器，是用PHP内置函数 **htmlspecialchars** 来实现的，具体可以点击 [这里](https://twig.symfony.com/doc/2.x/filters/escape.html) 了解 **escape** 过滤器， **htmlspecialchars** 函数定义如下：

> [ **htmlspecialchars** ](http://php.net/manual/zh/function.htmlspecialchars.php) ：(PHP 4, PHP 5, PHP 7)
>
> **功能** ：将特殊字符转换为 HTML 实体
>
> **定义** ：string **htmlspecialchars** ( string `$string` [, int `$flags` = ENT_COMPAT | ENT_HTML401 [, string`$encoding` = ini_get("default_charset") [, bool `$double_encode` = **TRUE** ]]] )
>
> ```bash
> & (& 符号)  ===============  &amp;
> " (双引号)  ===============  &quot;
> ' (单引号)  ===============  &apos;
> < (小于号)  ===============  &lt;
> > (大于号)  ===============  &gt;
> ```

第二处过滤在 **第17行** ，这里用了 **filter_var** 函数来过滤 **nextSlide** 变量，且用了 **FILTER_VALIDATE_URL** 过滤器来判断是否是一个合法的url，具体的 **filter_var** 定义如下：

>[ **filter_var** ](http://php.net/manual/zh/function.filter-var.php)： (PHP 5 >= 5.2.0, PHP 7)
>
>**功能** ：使用特定的过滤器过滤一个变量
>
>**定义** ：[mixed](http://php.net/manual/zh/language.pseudo-types.php#language.types.mixed) **filter_var** ( [mixed](http://php.net/manual/zh/language.pseudo-types.php#language.types.mixed) `$variable` [, int `$filter` = FILTER_DEFAULT [, [mixed](http://php.net/manual/zh/language.pseudo-types.php#language.types.mixed) `$options` ]] )

> **FILTER_VALIDATE_URL** 过滤器是如何判断一个 url 是否合法呢？这是一个好问题.....

针对这两处的过滤，我们可以考虑使用 **javascript伪协议** 来绕过。为了让大家更好理解，请看下面的demo代码：

![2](2.png)

我们使用 **payload** ：`?nextSlide=javascript://comment％250aalert(1)` ，可以执行 **alert** 函数：

![3](3.png)

实际上，这里的 **//** 在 JavaScript 中表示单行注释，所以后面的内容均为注释，那为什么会执行 **alert** 函数呢？那是因为我们这里用了字符 **%0a** ，该字符为换行符，所以 **alert** 语句与注释符 **//** 就不在同一行，就能执行。当然，这里我们要对 **%** 百分号编码成 **%25** ，因为程序将浏览器发来的payload：`javascript://comment％250aalert(1)` 先解码成： `javascript://comment%0aalert(1)` 存储在变量 **$url** 中（上图第二行代码），然后用户点击 a 标签链接就会触发 **alert** 函数。

## 实例分析-Anchor 0.9.2 XSS 漏洞

本次实例分析，我们选取的是 **Anchor 0.9.2** 版本。

> 关于该 CMS 的介绍可以参看[官方文档](http://anchorcms.com/docs/theming/introduction/)。

在该版本中，当用户访问一个不存在的URL链接时，程序会调用 404 模板，而这个模板则存在 XSS 漏洞，具体代码如下：

![4](4.png)

该代码在 **themes\default\404.php** 中，看第4行 **code** 标签中的 **current_url()** 函数，我们可在 **anchor\functions\helpers.php** 文件中看到 **current_url** 函数是由 **Uri** 类的  **current** 方法实现的，具体代码如下：

```php
function current_url() {
	return Uri::current();
}
```

我们跟进到 **Uri** 类，在 **system\uri.php** 文件中，我们发现这里调用了 **static::detect** 方法( **statci::** 是在PHP5.3版本之后引入的延迟静态绑定写法)。

![5](5.png)

在 **current** 方法下面，我们就可以找到 **detect** 方法，该方法会获取 **$_SERVER** 数组中的 **'REQUEST_URI' 、'PATH_INFO', 、'ORIG_PATH_INFO'** 三个键的值(下图第3-4行代码)，如果存在其中的某一个键，并且符合 **filter_var($uri, FILTER_SANITIZE_URL)** 和 **parse_url($uri, PHP_URL_PATH)** ，则直接将 **$uri** 传入 **static::format** 方法(下图第10-14行代码，具体代码如下：

![6](6.png)

我们跟进 **static::format** 方法，可以发现程序过滤了三次(下图第 3-7 行)，但是都没有针对 XSS 攻击进行过滤，只是为了获取用户访问的文件名，具体代码如下：

![7](7.png)

![image-20230417200906958](image-20230417200906958.png)

由于没有针对 XSS 攻击进行过滤，导致攻击十分容易，我们来看看 XSS 攻击具体是如何进行的。

### 环境搭建

- php 5.4.45
- apache 2.4.39
- MySQL 5.5.29
- 先在本地搭建一个名为 anchor 的数据库
- 管理员账号密码 admin admin123
- ```http
  127.0.0.1:800/PHP_Audit/RedSun/DAY2/anchor-cms-0.9.2/index.php
  ```

  

![image-20230417203050598](image-20230417203050598.png)

![image-20230417203249479](image-20230417203249479.png)

![image-20230417203314356](image-20230417203314356.png)

![image-20230417203348712](image-20230417203348712.png)

![image-20230417203440632](image-20230417203440632.png)

最后的管理员页面获取官方的文件有点异常，但是无伤大雅

![image-20230417203534128](image-20230417203534128.png)

去主页准备发起攻击

![image-20230417203612736](image-20230417203612736.png)



### Anchor 结构

一直有一个问题，该 cms 是如何实现访问不存在的路径就会调用404模板的呢？

- 入口文件：根目录下的 index.php
- 



### 漏洞利用

其实最难的地方在于漏洞的入口点在什么地方？如何能让代码进入 404.php ？这个最核心的问题红日没有给出来，我想这也是大家都不秘传的诀窍。

![image-20230417210456476](image-20230417210456476.png)

我们构造payload如下：  `http://localhost/anchor/index.php/<script>alert('www.sec-redclub.com')</script>` 。根据上面的分析，当我们访问这个并不存在的链接时，程序会调用404模板页面，然后调用 **current_url** 函数来获取当前用户访问的文件名，也就是最后一个 **/** 符号后面的内容，所以最终payload里的 `<script>alert('www.sec-redclub.com')</script>` 部分会嵌入到 `<code>` 标签中，造成 XSS 攻击，效果图如下：

![8](8.png)

### 修复建议

这对XSS漏洞，我们最好就是过滤关键词，将特殊字符进行HTML实体编码替换，这里给出的修复代码为Dedecms中防御XSS的方法，大家可以在 **uploads/include/helpers/filter.helper.php** 路径下找到对应代码，具体防护代码如下：

![9](9.png)

## 结语

看完了上述分析，不知道大家是否对 **filter_var** 函数绕过有了更加深入的理解，文中用到的CMS可以从 [这里](https://github.com/anchorcms/anchor-cms/releases?after=0.9.3-a) 下载，当然文中若有不当之处，还望各位斧正。如果你对我们的项目感兴趣，欢迎发送邮件到 hongrisec@gmail.com 联系我们。 **Day2** 的分析文章就到这里，我们最后留了一道CTF题目给大家练手，题目如下：

```php
// index.php
<?php 
$url = $_GET['url'];
if(isset($url) && filter_var($url, FILTER_VALIDATE_URL)){
    $site_info = parse_url($url);
    if(preg_match('/sec-redclub.com$/',$site_info['host'])){
        exec('curl "'.$site_info['host'].'"', $result);
        echo "<center><h1>You have curl {$site_info['host']} successfully!</h1></center>
              <center><textarea rows='20' cols='90'>";
        echo implode(' ', $result);
    }
    else{
        die("<center><h1>Error: Host not allowed</h1></center>");
    }

}
else{
    echo "<center><h1>Just curl sec-redclub.com!</h1></center><br>
          <center><h3>For example:?url=http://sec-redclub.com</h3></center>";
}

?>
```

```php
// f1agi3hEre.php
<?php  
$flag = "HRCTF{f1lt3r_var_1s_s0_c00l}"
?>
```

题解我们会阶段性放出，如果大家有什么好的解法，可以在文章底下留言，祝大家玩的愉快！

## 相关文章

[Anchor CMS 0.9.2: XSS](https://curesec.com/blog/article/blog/Anchor-CMS-092-XSS-53.html)




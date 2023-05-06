###### tags: `Web 安全`

# 芜风web安全学习路线

# **WEB**

## **学习指南**

## **Web 安全学习路线**

### **基础的学习路线**

- 其实在最开始学习的时候会遇到一个比较头疼的问题：PHP 到底要不要学，我这里的建议是要学，但无需过于深入。

当然，萝卜青菜各有所爱，我说的也不一定是对的，师傅们可以自行抉择 ~

#### **先从开发学起，起码要先熟悉 PHP 的基础语法**

[PHP 菜鸟教程](https://www.runoob.com/php/php-tutorial.html) 先 mark 一下，如果需要用到再来看，无需系统地学习 PHP。

尝试用 PHP 自己开发一个项目（我的建议是先开发一下），或者对 PHP 项目进行代码审计，资源可以看 “b站大学” 与 GitHub。

关于 PHP 开发的项目实战：https://www.bilibili.com/video/BV1f64y1Z71f/?spm_id_from=333.880.my_history.page.click

可以用 PHP 进行简单项目的开发之后，可以看一些简单的漏洞，也就是基础的漏洞，弱类型这种的。

PHP 基础漏洞这里推荐一个 GitHub 的项目：

https://github.com/bowu678/php_bugs

对应的讲解可以参考我的文章：[PHP 基础漏洞](https://drun1baby.github.io/2022/08/17/PHP-入门基础漏洞/)

#### **Owasp TOP 10 漏洞的学习**

以下内容都比较基础，如需拓展可自行安排，可以看 Chybeta 师傅的 GitHub 项目：https://github.com/CHYbeta/Web-Security-Learning

如需靶场实战推荐这一个网址：[PortSwigger ---- 也是 Burpsuite 的开发者](https://portswigger.net/web-security/all-materials)

- #####    **SQL 注入：**

-  [SQLI labs 靶场精简学习记录](https://www.sqlsec.com/2020/05/sqlilabs.html)

- ##### **XSS****：**

-  [XSS 从零开始](https://www.sqlsec.com/2020/01/xss.html)

- #####    **CSRF****：**

-  [从0到1完全掌握CSRF](https://drun1baby.github.io/2022/05/08/从0到1完全掌握CSRF/)

- ##### **SSRF****：**

-  [从一文中了解SSRF的各种绕过姿势及攻击思路](https://tttang.com/archive/1648/)

- ##### **目录遍历：**

-  [从0到1完全掌握目录遍历漏洞](https://drun1baby.github.io/2022/03/22/从0到1完全掌握目录遍历漏洞/)

- ##### **XXE：**

- #####  [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)

​          [从0到1完全掌握XXE](https://drun1baby.github.io/2022/04/19/从0到1完全掌握XXE/)

- #####    **SSTI****：**

-  [Jinja2 template injection filter bypasses](https://0day.work/jinja2-template-injection-filter-bypasses/)

-  [乱弹Flask注入](http://www.freebuf.com/articles/web/88768.html)

-  [服务端模板注入攻击 （SSTI）之浅析](http://www.freebuf.com/vuls/83999.html)

-  [Exploring SSTI in Flask/Jinja2](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/)

-  [Flask Jinja2开发中遇到的的服务端注入问题研究](http://www.freebuf.com/articles/web/136118.html)

-  [FlaskJinja2 开发中遇到的的服务端注入问题研究 II](http://www.freebuf.com/articles/web/136180.html)

-  [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)

-  [Injecting Flask](https://nvisium.com/blog/2015/12/07/injecting-flask/)

-  [Server-Side Template Injection: RCE for the modern webapp](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)

-  [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.jp/2016/11/exploiting-python-code-injection-in-web.html)

-  [利用 Python 特性在 Jinja2 模板中执行任意代码](http://rickgray.me/2016/02/24/use-python-features-to-execute-arbitrary-codes-in-jinja2-templates/)

-  [Python 模板字符串与模板注入](https://virusdefender.net/index.php/archives/761/)

-  [Ruby ERB Template Injection](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)

-  [服务端模板注入攻击](https://zhuanlan.zhihu.com/p/28823933)

- ##### **文件包含**

-  [php文件包含漏洞](https://chybeta.github.io/2017/10/08/php文件包含漏洞/)

-  [Turning LFI into RFI](https://l.avala.mp/?p=241)

-  [PHP文件包含漏洞总结](http://wooyun.jozxing.cc/static/drops/tips-3827.html)

-  [常见文件包含发生场景与防御](https://www.anquanke.com/post/id/86123)

-  [zip或phar协议包含文件](https://bl4ck.in/tricks/2015/06/10/zip或phar协议包含文件.html)

-  [文件包含漏洞 一](http://drops.blbana.cc/2016/08/12/e6-96-87-e4-bb-b6-e5-8c-85-e5-90-ab-e6-bc-8f-e6-b4-9e/)

-  [文件包含漏洞 二](http://drops.blbana.cc/2016/12/03/e6-96-87-e4-bb-b6-e5-8c-85-e5-90-ab-e6-bc-8f-e6-b4-9e-ef-bc-88-e4-ba-8c-ef-bc-89/)

- ##### **文件上传 / 解析漏洞**

-  [Upload-labs通关手册](https://xz.aliyun.com/t/2435)

-  [文件上传和WAF的攻与防](https://www.secfree.com/article-585.html)

-  [我的WafBypass之道（upload篇）](https://xz.aliyun.com/t/337)

-  [文件上传漏洞（绕过姿势）](http://thief.one/2016/09/22/上传木马姿势汇总-欢迎补充/)

-  [服务器解析漏洞](http://thief.one/2016/09/21/服务器解析漏洞/)

-  [文件上传总结](https://masterxsec.github.io/2017/04/26/文件上传总结/)

-  [代码审计之逻辑上传漏洞挖掘](http://wooyun.jozxing.cc/static/drops/papers-1957.html)

-  [渗透测试方法论之文件上传](https://bbs.ichunqiu.com/thread-23193-1-1.html?from=sec)

-  [关于文件名解析的一些探索](https://landgrey.me/filetype-parsing-attack/)

-  [Web安全 — 上传漏洞绕过](http://www.freebuf.com/column/161357.html)

-  [上传绕过WAF](http://docs.ioin.in/writeup/www.am0s.com/_jchw_376_html/index.html)

### **Web 进阶学习**

学完了上述的基础内容之后，就可以学习一点进阶的内容了，比如 PHP 伪协议，反序列化，POP 链这种。

#### **关于 PHP 的进阶学习**

- ##### **伪协议**

-  [谈一谈php://filter的妙用](https://github.com/CHYbeta/Web-Security-Learning/blob/master/www.leavesongs.com/PENETRATION/php-filter-magic.html)

-  [php 伪协议](http://lorexxar.cn/2016/09/14/php-wei/)

-  [利用 Gopher 协议拓展攻击面](https://blog.chaitin.cn/gopher-attack-surfaces/)

-  [PHP伪协议之 Phar 协议（绕过包含）](https://www.bodkin.ren/?p=902)

-  [PHP伪协议分析与应用](http://www.4o4notfound.org/index.php/archives/31/)

-  [LFI、RFI、PHP封装协议安全问题学习](http://www.cnblogs.com/LittleHann/p/3665062.html)

- ##### **序列化**

-  [PHP反序列化漏洞](http://bobao.360.cn/learning/detail/4122.html)

-  [浅谈php反序列化漏洞](https://chybeta.github.io/2017/06/17/浅谈php反序列化漏洞/)

-  [PHP反序列化漏洞成因及漏洞挖掘技巧与案例](http://bobao.360.cn/learning/detail/3193.html)

- ##### **PHP 代码审计**

-  [PHP漏洞挖掘——进阶篇](http://blog.nsfocus.net/php-vulnerability-mining/)

-  [论PHP常见的漏洞](http://wooyun.jozxing.cc/static/drops/papers-4544.html)

-  [浅谈代码审计入门实战：某博客系统最新版审计之旅](http://www.freebuf.com/articles/rookie/143554.html)

-  [ctf中的php代码审计技巧](http://www.am0s.com/ctf/200.html)

-  [PHP代码审计tips](http://docs.ioin.in/writeup/www.91ri.org/_15074_html/index.html)

-  [代码审计之文件越权和文件上传搜索技巧](http://docs.ioin.in/writeup/blog.heysec.org/_archives_170/index.html)

-  [PHP代码审计入门集合](http://wiki.ioin.in/post/group/6Rb)

-  [PHP代码审计学习](http://phantom0301.cc/2017/06/06/codeaudit/)

-  [PHP漏洞挖掘思路+实例](http://wooyun.jozxing.cc/static/drops/tips-838.html)

-  [PHP漏洞挖掘思路+实例 第二章](http://wooyun.jozxing.cc/static/drops/tips-858.html)

-  [浅谈代码审计入门实战：某博客系统最新版审计之旅](http://www.freebuf.com/articles/rookie/143554.html)

-  [PHP 代码审计小结 (一)](https://www.chery666.cn/blog/2017/12/11/Code-audit.html)

-  [2018 PHP 应用程序安全设计指北](https://laravel-china.org/articles/7235/2018-php-application-security-design)

PHP 代码审计还是比较重要的，如果 PHP 代码审计的基础好的话，审计起 Java 项目也算是有点基础，会相对来说轻松一点。

#### **关于 Java 安全**

这里我整理了一条学习路线给师傅们，GitHub 的地址在这里  [Java 安全学习路线](https://github.com/Drun1baby/JavaSecurityLearning)

##### **先从开发学起**

推荐的是这些

先学 Springboot[【狂神说Java】SpringBoot最新教程IDEA版通俗易懂](https://www.bilibili.com/video/BV1PE411i7CV)，前面部分是 Thymeleaf 模板引擎的开发，后面是一些组件的基本使用，很基础。

学一下 vue：[尚硅谷Vue2.0+Vue3.0全套教程丨vuejs从入门到精通](https://www.bilibili.com/video/BV1Zy4y1K7SH?spm_id_from=333.788.top_right_bar_window_custom_collection.content.click)

学完这两个之后可以自己过一个小项目[【实战】基于SpringBoot+Vue开发的前后端分离博客项目完整教学](https://www.bilibili.com/video/BV1PQ4y1P7hZ?vd_source=a4eba559e280bf2f1aec770f740d0645)

学完这些内容最多花费两个月时间。

如果中途有什么看不懂的，也可以推荐看 Java 基础，哪块不懂看哪块，二倍速走起看[【狂神说Java】Java零基础学习视频通俗易懂](https://www.bilibili.com/video/BV12J41137hu?spm_id_from=333.337.search-card.all.click)

##### **Java 基础**

可以看b站白日梦组长的视频，讲的非常好

[Java反序列化漏洞专题-基础篇(21/09/05更新类加载部分)](https://www.bilibili.com/video/BV16h411z7o9?spm_id_from=333.788.top_right_bar_window_custom_collection.content.click)

[Java-IO流](https://drun1baby.github.io/2022/05/30/Java-IO流/)

[反射](https://drun1baby.github.io/2022/05/20/Java反序列化基础篇-02-Java反射与URLDNS链分析/)

[JDK动态代理](https://drun1baby.github.io/2022/06/01/Java反序列化基础篇-04-JDK动态代理/)

[反序列化概念与利用](https://drun1baby.github.io/2022/05/17/Java反序列化基础篇-01-反序列化概念与利用/)

[URLDNS链分析](https://drun1baby.github.io/2022/05/20/Java反序列化基础篇-02-Java反射与URLDNS链分析/)

[类的动态加载](https://drun1baby.github.io/2022/06/03/Java反序列化基础篇-05-类的动态加载/)

一开始学还是会有点懵的，学到后面自然而然就会了

##### **Java 反****序列化****基础**

接着就可以开始 CC 链了；CC 链是 1-6-3-2-4-5-7

还有一个 CC11；这一块 CC 链的学习要多自己总结，有利于后续的学习。

- 视频同样推荐 b 站白日梦组长的视频

[CC1链](https://drun1baby.github.io/2022/06/06/Java反序列化Commons-Collections篇01-CC1链/)

[CC1链补充](https://drun1baby.github.io/2022/06/10/Java反序列化Commons-Collections篇02-CC1链补充/)

[CC6链](https://drun1baby.github.io/2022/06/11/Java反序列化Commons-Collections篇03-CC6链/)

[CC3链](https://drun1baby.github.io/2022/06/20/Java反序列化Commons-Collections篇04-CC3链/)

[CC2链](https://drun1baby.github.io/2022/06/28/Java反序列化Commons-Collections篇05-CC2链/)

[CC4链](https://drun1baby.github.io/2022/06/28/Java反序列化Commons-Collections篇06-CC4链/)

[CC5链](https://drun1baby.github.io/2022/06/29/Java反序列化Commons-Collections篇07-CC5链/)

[CC7链](https://drun1baby.github.io/2022/06/29/Java反序列化Commons-Collections篇08-CC7链/)

[CC11链](https://drun1baby.github.io/2022/07/11/Java反序列化Commons-Collections篇09-CC11链/)

[CommonsBeanUtils反序列化](https://drun1baby.github.io/2022/07/12/CommonsBeanUtils反序列化/)

CC 链部分结束，进入 shiro 部分，shiro 之前我们已经走过开发了，所以理解起来很简单。

[Shiro550流程分析](https://drun1baby.github.io/2022/07/10/Java反序列化Shiro篇01-Shiro550流程分析/)

Shiro 721 的可能后续会学习吧，现在先不学习。

进入到新的阶段

##### **Java 反****序列化****进阶**

- 这块是基础中的基础，但是也很难，要静下心来学的。

[RMI基础](https://drun1baby.github.io/2022/07/19/Java反序列化之RMI专题01-RMI基础/)

[RMI的几种攻击方式](https://drun1baby.github.io/2022/07/23/Java反序列化之RMI专题02-RMI的几种攻击方式/)

[JNDI学习](https://drun1baby.github.io/2022/07/28/Java反序列化之JNDI学习/)

LDAP 是包含在 JNDI 里面的

学完上面的之后就可以开始学习其他的了。
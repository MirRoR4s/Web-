# Three

## 前言

- 本期来到 TIER1 系列的第五个靶机，难度评级为 Very Easy！

在当前时代，各种企业，无论大小都在使用云。它们主要用云进行数据备份、数据存储、数据的灾难恢复、邮箱、虚拟桌面、软件开发和测试等等。所以为了应对可能的攻击，对公司的云进行一个安全地配置是一件很重要的事情。

Three 靶机包含了一个网站，并使用一个 AWS S3 bucket 作为它的云存储服务设备。但是这个 bucket 未进行安全配置，所以我们可以在这个 bucket 上上传一个反弹 shell，从而读取 flag 并通过本关。



## 枚举

首先我们扫描靶机上开放的端口：

```bash
sudo nmap -sV ip
```

![image-20230507203642068](picture/image-20230507203642068.png)

扫描结果显示 TCP  的 22 和 80 端口是开放的。我们在浏览器访问一下靶机的 80 端口：

![image-20230507203746821](picture/image-20230507203746821.png)

我们可以看到一个静态的 web 页面，其中有一个音乐会门票预订部分，但是并没有什么用处。

我们使用 [Wappalyzer](https://www.wappalyzer.com/apps/) 识别一下网站采用了什么技术：

![image-20230507204102271](picture/image-20230507204102271.png)

识别结果告诉我们网站基于 PHP 语言开发！

在页面一番搜索，可以发现一个 Contact 功能，点击一下就来到了 Contact 页面：

![image-20230507204304879](picture/image-20230507204304879.png)

从上图可以看到邮箱中的一个域名信息

```
thetoppers.htb
```

现在，在我们的 /etc/hosts 文件中增添配置，将以上域名和靶机的 IP 关联起来：

```bash
echo "10.129.227.248 theoppers.htb" | sudo tee -a /etc/hosts
```

这样，我们就可以通过浏览器直接访问该域名了。

> /etc/hosts 文件用于将主机名解析为 IP 地址。默认情况下，在 DNS 服务器进行域名解析前会查询该文件。
>
> 所以我们需要在该文件中为以上域名添加一个对应的 IP，这样我们的浏览器就会将该域名解析成我们添加的 IP 啦！

## 子域名枚举

#### 子域名是什么？

子域名是被添加到网站域名开头的额外信息块。子域名允许网站根据特定的功能来分离和组织内容。

举个例子，若我们访问 hackthebox.com ，我们可以访问到网站的主页面部分。但是如果我们访问 ctf.hackthebox.com，我们就能访问到网站的 CTF 部分。在这种情况下，`ctf` 就是子域名，而 `hackthebox` 则是主域名，`com` 是顶级域名。尽管 URL 发生了一些轻微的变化，但是你仍在 HTB 的网站内，在 HTB 的域名下。

通常，不同的子域名会有不同的 IP 地址，当我们的系统查找子域名时，它会得到管理该应用程序的服务器的地址。。

有时一个服务器可能管理着多个子域名，这是通过基于主机的路由实现的（或者是虚拟主机路由），服务器会根据 HTTP 请求中的 Host 字段来确定让哪个应用程序处理该请求。

现在我们拥有 `thetoppers.htb` 域名，让我们枚举一下靶机的服务器上是否还有其他的子域名。有许多不同的子域名枚举工具，比如 `gobuster`、`wfuzz`、`feroxbuster` 等等，本篇 WP 使用 `gobuster` 以下命令进行子域名枚举。

```bash
gobuster vhost -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb
```

几个选项的含义如下：

- vhost：使用 VHOST 进行暴力破解
- -w：字典路径
- -u：指定 URL

> 注意：若使用 Gobuser 3.2.0 以上版本，还需要在命令后面加上 --append-domain 选项，这样才能进行子域名的枚举。具体没太看懂，似乎加了这个选项，才会把字典里面的元素添加到要枚举的域名前面。比如现在我们是 thetoppers.htb，加了选项才会把字典里面的 word 加在域名前面变成 word.thetoppers.htb

对于字典里面的每个单词，Gobuster 会发送具有如下 Host 头的请求：

```http
Host: [word].thetoppers.htb
```

命令运行后 Gobuster 会记录默认的响应，并显示任何返回不同内容的响应。

![image-20230508093247778](picture/image-20230508093247778.png)

结果显示存在一个名为 `s3.thetoppers.htb` 的子域名，我们继续在 /etc/hosts 文件中把该子域名和靶机的 IP 关联起来：

```bash
echo "10.129.227.248 s3.thetoppers.htb" | sudo tee -a /etc/hosts
```

之后使用浏览器访问 `s3.thetoppers.htb`

![image-20230508093411714](picture/image-20230508093411714.png)

只响应给我们一个 JSON 字符串

```
{"status": "running"}
```



## S3 bucket 是什么？

谷歌搜索一下上述回显的信息，关键字是：`s3 subdomain status running`。

![image-20230508093935403](picture/image-20230508093935403.png)

谷歌告诉我们该响应信息意味着 `S3` 是一个基于云的对象存储服务，其允许我们在一个称为 buckets 的容器内存储东西。AWS S3 buckets 有很多用途，比如数据备份和存储、软件交付、静态网站。存储在 Amazon S3 bucket 内的文件被称为 S3 对象。

我们可以利用 `awscli` 工具和 S3 bucket 进行交互。在 linux 中可以通过以下命令安装 awscli：

```bash
sudo apt install awscli
```

安装完毕后通过以下命令配置 awscli：

```
aws configure
```

![image-20230508094357711](picture/image-20230508094357711.png)

要求我们输入的配置项有 AWS 服务器的访问密钥 ID、访问密钥等等。在这里我们使用任意值来配置任何字段，因为有时候 AWS 服务器可能被配置为不进行身份认证，这样不需要密钥也可以访问。

我们可以通过 `ls` 命令列出靶机服务器所持有的全部 S3 buckets：

```bash
aws --endpoint=http://s3.thetoppers.htb s3 ls
```


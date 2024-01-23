# passwallLogViewer

passwallLogViewer 是一个实用的工具，它能够读取位于 `/var/etc/passwall/TCP.log` 的 passwall 日志文件，并提供一个基于 Web 的界面来实时查看 passwall 的连接状态。这个工具特别适合需要监控和分析 passwall 连接情况的用户。

## 功能特点

- 监控 passwall 日志文件。
- 实时展示 passwall 的连接情况。
- 通过 web 界面轻松查看日志信息。
- 监听本地 5032 端口提供 Web 服务。

## 预览图

![passwallLogViewer预览](https://github.com/puteulanus/passwallLogViewer/assets/4849177/e580b5b4-95c7-4a48-afd4-b8aa39f084b0)

## 安装

在开始使用 passwallLogViewer 之前，你需要确保你的系统中安装了 Python 3 和相应的依赖包。

### 安装 Python 依赖

通过以下命令安装所需的 Python 包：

```bash
pip install pytz flask
```

### 克隆项目

```bash
git clone https://github.com/puteulanus/passwallLogViewer.git
cd passwallLogViewer
```

## 配置

确保你的 passwall 日志等级已经设置为 `Info` 等级，以便程序能够正确读取连接信息。

## 使用

启动 passwallLogViewer 服务：

```bash
python passwallLogViewer.py
```

之后，你可以在浏览器中访问 `http://[你的路由器IP]:5032` 来查看 passwall 的连接情况。

## 注意

Info 等级的日志文件大小增加很快，可以设置 cron 定时清空 `/var/etc/passwall/TCP.log` 文件
```
0 * * * * echo "" > /var/etc/passwall/TCP.log
```

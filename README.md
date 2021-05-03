# simple-dns-client
A simple dns client

client.cpp为一个简单的交互式dns客户端的实现，test.cpp为压力测试的实现，两者为使用该解析库提供了范例。thread_pool.h为附带的一个线程池实现，也可以更换为其他线程池实现。

include文件夹中为解析库的实现，其中dns_resolver.h为解析库的核心。使用时只需引入dns_resolver.h即可；dns_util.h包含了一些常用的工具函数。

include/portable文件夹中为跨平台功能的相关实现。

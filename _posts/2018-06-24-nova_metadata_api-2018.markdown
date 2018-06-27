---
layout: post

title: "OpenStack metadata服务机制"

subtitle: ""

date: 2018-06-24 18:22:00

author:     "Jobin"
header-img: "img/post-bg-2018-624.jpg"
catalog: true
tags:
    - Nova-metadata-api
---

# metadata概念

​	在创建虚拟机的时候，用户往往需要对虚拟机进行一些配置，比如：开启服务、安装某些包、添加ssh密钥、配置hostname等。在OpenStack中，配置信息分为两类：metadata和user data。

（1）metadata主要包括虚拟机自身的一些常用属性，如hostname、网络配置信息、ssh登录密钥等，主要以键值对的形式存在。

（2）user data主要包括一些命令、脚本等，user data通过文件传递，并支持多种文件格式，包括gzip压缩文件、shell脚本（自定义启动脚本）、cloud-init配置文件等。

​	虽然metadata和user data并不相同，但是OpenStack向虚拟机提供这两种信息的机制是一致的，只是虚拟机在获取到信息后，对两者的处理方式不同，两者可以统称为metadata。

# metadata获取机制

​	在OpenStack中，虚拟机获取metadata信息的方式有两种：config drive和metadata Restful服务。

​	config drive机制主用于配置虚拟机的网络信息，包括IP、子网掩码、网关等。当虚拟机无法通过dhcp正确获取网络信息时，config drive是获取metadata信息的必要方式；如果虚拟机能够自动正确配置网络，那么可以通过restful服务的方式获取metadata信息。

​	有关config driver机制暂未进行深入研究，主要讨论metadata restful方式。

## 1、config drvier

​	Config driver机制是指OpenStack将metadata信息写入虚拟机的一个特殊配置设备中，然后在虚拟机启动时，自动挂载并读取metadata信息，从而达到获取metadata的目的

## 2、metadata restful服务

​	OpenStack提供了restful接口，虚拟机可以通过rest api来获取metadata信息。提供该服务的组件为：nova-metadata-api(由nova-api启动，无需单独开启该服务)。当然，要完成从虚拟机至网络节点的请求发送和相应，只有nova-metadata-api服务是不够的，还需要neutron-metadata-agent和neutron-ns-metadata-proxy。

### metadata服务相关功能

（1）nova-metadata-api

​	nova-metadata-api启动了restful服务，负责处理虚拟机发送来的rest api请求，从请求的http头部中取出相应的信息，获取虚拟机的id，继而从数据库中读取虚拟机的metadata信息，最后将结果返回。这个和nova api类似，是nova的api的一部分，通常使用8775端口，服务接收neutron-metadata-agent的request。

（2）neutron-metadata-agent

​	neutron-metadata-agent运行在网络节点，负责将接收到的获取metadata请求转发给nova-metadata-api。neutron-metadata-agent会获取虚拟机和租户的id，添加到请求的http头部中，nova-metadata-api会根据这些信息返回metadata响应数据。

（3）neutron-ns-metadata-proxy

​	neutron-ns-metadata-proxy也运行在网络节点，为了解决网络节点的网段和租户的虚拟机网段重复的问题，OpenStack引入了网络命名空间。Neutron中的路由和dhcp服务器都在各自独立的命名空间中。由于虚拟机获取metadata的请求都是以路由和dhcp服务作为网络出口，所以需要通过neutron-ns-metadata-proxy连通不同的网络命名空间，将请求在网络命名空间之间转发。neutron-ns-metadata-proxy利用在unix domain socket之上的http技术，实现了不同网络命名空间之间的http请求转发，并在请求中添加‘X-Neutron-Router-ID’和‘X-Neutron-Network-ID’信息，以便neutron-metadata-agent来辨别发送请求的虚拟机，获取虚拟机的id。

### metadata请求发送流程

![metadata](https://helloworldjhb.github.io/img/nova-api-metadata/metadata.png)

Step1: instance启动的时候会发起http请求到metadata service，地址为"http://169.254.169.254:80"；请求被发送至neutron-ns-metadata-proxy，此时会在请求中添加router-id和network-id；

Step2,3:请求通过unix domain socket 被转发给neutron-metadata-agent，根据请求中的router-id、network-id和ip，获取port信息，从而拿到instance-id和tenant-id加入请求中；

Step4,5:请求被转发给nova-api-metadata，其利用instance-id和tenant-id获取虚拟机的metadata，返回响应数据。

### instance发送请求方式

metadata请求发送流程中第一步过程

（1）通过router发送请求

​	subnet连接到router上时，指定的网关将会处理所有实例的路由请求，包括到metadata server。此时当虚拟机发送http请求http://169.254.169.254到metadata service，router会做路由决策(查询iptables chains和rules)。

​	虚拟机所在subnet连接到了路由器上，则发往169.254.169.254的报文会被发至router，neutron通过router所在网络命名空间添加iptables规则，将该报文转发至9697端口。

![img1](https://github.com/helloworldjhb/helloworldjhb.github.io/blob/master/img/nova-api-metadata/img1.png)

​	监听在9697端口上的neutron-ns-metadata-proxy服务，该服务获取请求报文，进而进入上述流程图中的后续处理和转发流程

![img2](https://github.com/helloworldjhb/helloworldjhb.github.io/blob/master/img/nova-api-metadata/img2.png)

（2）通过dhcp发送请求

​	设置/etc/neutron/dhcp_agent.ini中enable_isolated_metadata=True

​	如果虚拟机所在subnet没有连接到任何router上，那么请求无法通过router转发，此时neutron通过dhcp服务器来转发metadata请求。dhcp服务通过dhcp协议的选项121来为虚拟机设置静态路由。

​	虚拟机启动时的请求过程：

​	1.虚拟机启动，dhcp在vm中注入一条静态路由到metadata service，前提是设置enable_isolated_metadata=True（dhcp服务器通过classless-static-route DHCP选项，通常是121，注入一条到metadata service的路由）。

​	2.向169.254.169.254的80端口发送metadata请求，会发送到network node上的dhcp namespace里的neutron-ns-metadata-proxy。

​	3.neutron-ns-metadata-proxy为消息添加X-Neutron-Network-ID和X-Forward-For头部，分别是network-id和instance-id。

​	4.通过unix domian socket发送给neutron-metadata-agent。

​	5.neutron-metadata-agent向nova metadata api service请求，然后metadata service向nova-conductor查询数据库信息返回给neutron-metadata-agent，再由neutron-metadata-agent返回给neutron-ns-metadata-proxy，最后返回给vm。

​	查看dhcp服务器，dhcp namespace中，dhcp port上有2个ip: dhcp本身ip，metadata默认的IP（169.254.169.254）。

​	虚拟机获取dhcp配置时，会启动dnsmasq进程，同时启动namespace以及enable_isolated_metadata=True时，会在该命名空间中运行metadata namespace proxy进程监听tcp的80端口。

### 说明

1. 在创建网络时，参数admin-state-up如果设置为false，则dhcp和metadata服务不可用（待研究）
2. router-interface-delete将subnet取消与路由器连接后，需要重启network node上的服务（否则，向dhcp发送的metadata请求响应不了）
3. 修改enable_isolated_metadata=false我true后，需要重启dhcp服务










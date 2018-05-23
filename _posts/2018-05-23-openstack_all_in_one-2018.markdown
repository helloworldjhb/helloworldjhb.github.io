---

layout: post

title: "用DevStack安装OpenStack(单机)"

subtitle: ""

date: 2018-05-23 22:17:00

author:     "Jobin"
header-img: "img/post-bg-2018-513.jpg"
catalog: true
tags:
    - OpenStack

---

OpenStack是一个开源的云计算管理平台项目，由几个主要的组件组合起来完成具体工作。但是安装OpenStack却不是那么容易的，让许多初学者望而却步。想体验一下OpenStack的魅力，可以使用DevStack来安装OpenStack。

# 操作步骤

## 安装CentOS

下载镜像，然后在虚拟机中安装，至少需要安装OpenSSH Server，方便远程连接。



## 配置网络

OpenStack至少需要两个网卡，一个用于连接外部网络，一个用于连接内部网络。

### 外部网络

供应商网络，外部或Internet可以访问的网络。

### 内部网络

管理网络，用于OpenStack组件以及MySQL DB Server, RabbitMQ messaging server之间的通信。租户网络和管理网络使用同一张网卡。

vmware虚拟机网络配置：

| 网络     | 名称   | 类型     | 子网IP      | 子网掩码      | 子网网关    |
| -------- | ------ | -------- | ----------- | ------------- | ----------- |
| 外部网络 | VMnet0 | 桥接模式 | 192.168.0.0 | 255.255.255.0 | 192.168.0.1 |
| 内部网络 | VMnet8 | NAT模式  | 10.0.0.0    | 255.255.255.0 | 10.0.0.2    |

 ## 配置pip源

```Shell
root@jhb:~# mkdir /root/.pip
root@jhb:~# vi /root/.pip/pip.conf

[global]
index-url=http://pypi.douban.com/simple/
trusted-host=pypi.douban.com
```

## 下载DevStack

安装git并下载最新版的devstack。

```Shell
root@jhb:~# apt-get install git   
root@jhb:~# cd /home
root@jhb:~# git clone http://git.trystack.cn/openstack-dev/devstack.git -b stable/queen
```

## 创建stack用户

目前DevStack脚本已经不支持直接使用root身份运行，你需要创建stack用户来运行。

在非root用户下创建stack用户并设置密码。

```shell
jhb@jhb:~$ sudo chown –R $USER:$USER /home/devstack
jhb@jhb:~$ cd /home/devstack/tools/
jhb@jhb:~$ sudo ./create-stack-user.sh
jhb@jhb:~$ sudo passwd stack
```

## 授权stack用户

在root用户下给stack用户授权。编辑/etc/sudoers，找到这一行 root ALL=(ALL:ALL) ALL，在下面加上一行 stack ALL=(ALL:ALL) ALL。

```Shell
root@jhb:~# vi /etc/sudoers

# User privilege specification
root ALL=(ALL:ALL) ALL
stack ALL=(ALL:ALL) ALL

root@jhb:~# chown –R stack:stack /home/devstack
root@jhb:~# chown –R stack:stack /opt/stack
```

## 创建local.conf文件

进入/home/devstack目录，编辑local.conf文件

```Shell
root@jhb:~# cd /home/devstack/
root@jhb:/home/devstack# vi local.conf
```

在文件中添加如下内容。网络的地方需要根据自己的实际情况修改。

```
[[local|localrc]]

# use TryStack git mirror
GIT_BASE=http://git.trystack.cn
NOVNC_REPO=http://git.trystack.cn/kanaka/noVNC.git
SPICE_REPO=http://git.trystack.cn/git/spice/spice-html5.git

#OFFLINE=True
RECLONE=True

# Define images to be automatically downloaded during the DevStack built process.
DOWNLOAD_DEFAULT_IMAGES=False
IMAGE_URLS="http://images.trystack.cn/cirros/cirros-0.3.4-x86_64-disk.img"

HOST_IP=192.168.0.15


# Credentials
DATABASE_PASSWORD=pass
ADMIN_PASSWORD=pass
SERVICE_PASSWORD=pass
SERVICE_TOKEN=pass
RABBIT_PASSWORD=pass

HORIZON_BRANCH=stable/queen
KEYSTONE_BRANCH=stable/queen
NOVA_BRANCH=stable/queen
NEUTRON_BRANCH=stable/queen
GLANCE_BRANCH=stable/queen
CINDER_BRANCH=stable/queen


#keystone
KEYSTONE_TOKEN_FORMAT=UUID

##Heat
HEAT_BRANCH=stable/queen
enable_service h-eng h-api h-api-cfn h-api-cw


## Swift
SWIFT_BRANCH=stable/queen
ENABLED_SERVICES+=,s-proxy,s-object,s-container,s-account
SWIFT_REPLICAS=1
SWIFT_HASH=011688b44136573e209e


# Enabling Neutron (network) Service
disable_service n-net
enable_service q-svc
enable_service q-agt
enable_service q-dhcp
enable_service q-l3
enable_service q-meta
enable_service q-metering
enable_service neutron

## Neutron options
Q_USE_SECGROUP=True
FLOATING_RANGE="192.168.0.0/24"
FIXED_RANGE="10.0.0.0/24"
NETWORK_GATEWAY="10.0.0.2"
Q_FLOATING_ALLOCATION_POOL=start=192.168.0.150,end=192.168.0.180
PUBLIC_NETWORK_GATEWAY="192.168.0.1"
Q_L3_ENABLED=True
PUBLIC_INTERFACE=eth0
Q_USE_PROVIDERNET_FOR_PUBLIC=True
OVS_PHYSICAL_BRIDGE=br-ex
PUBLIC_BRIDGE=br-ex
OVS_BRIDGE_MAPPINGS=public:br-ex

# #VLAN configuration.
Q_PLUGIN=ml2
ENABLE_TENANT_VLANS=True

# Logging
LOGFILE=/opt/stack/logs/stack.sh.log
VERBOSE=True
LOG_COLOR=True
SCREEN_LOGDIR=/opt/stack/logs
```

## 以stack用户身份运行脚本安装

```shell
root@jhb:/home/devstack# su stack
stack@jhb:/home/devstack$ ./stack.sh
```
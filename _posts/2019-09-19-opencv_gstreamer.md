---
layout: post

title: "ubuntu编译安装opencv，并支持gstreamer"

subtitle: ""

date: 2019-09-19 6:08:00

author:     "Jobin"
header-img: ""
catalog: true
tags:
    - Opencv-gstreamer
---

#ubuntu编译安装opencv，并支持gstreamer

##环境：

```
Ubuntu 18.04.3
Opencv 4.1.1
Gstreamer 1.14.5
或
Ubuntu 16.04.3
Opencv 4.1.0
Gstreamer 1.8.3
```

ubuntu服务器上执行如下命令：

```shell
1.基础包安装
# apt-get install gstreamer1.0 libgstreamer-plugins-base1.0-dev libgstreamer1.0-0 gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav gstreamer1.0-doc gstreamer1.0-tools libgtk2.0-dev libqt4-dev
2. 下载opencv4.1.1
# wget https://github.com/opencv/opencv/archive/4.1.1.zip
3. 解压缩
# unzip 4.1.1.zip
4. 编译安装
# cd opencv-4.1.1/
# mkdir build
# cmake -D CMAKE_BUILD_TYPE=RELEASE -D CMAKE_INSTALL_PREFIX=/usr/local -D INSTALL_PYTHON_EXAMPLES=ON -D INSTALL_C_EXAMPLES=OFF -D BUILD_EXAMPLES=ON -D BUILD_opencv_legacy=OFF -DWITH_IPP=OFF -DBUILD_opencv_python2=ON -DBUILD_opencv_python3=ON -DWITH_FFMPEG=ON -DWITH_GSTREAMER=ON -D WITH_QT=ON -DWITH_GTK=ON ..
# make -j$(nproc)
# sudo make install

# sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf.d/opencv.conf'
# sudo ldconfig
```

备注：

```
编译过程中会检查包安装情况：
Checking for modules 'libavcodec;libavformat;libavutil;libswscale'
Checking for module 'libavresample'
Checking for module 'gstreamer-base-1.0'
Checking for module 'gstreamer-app-1.0'
Checking for module 'gstreamer-riff-1.0'
Checking for module 'gstreamer-pbutils-1.0'
Checking for module 'libdc1394-2'
```




# pyqt

使用pyqt设计GUI程序

# 相关工具

* pyqt5       - 设计界面，生成python代码
* pyinstaller - 打包程序，生成二进制执行文件

## 使用方法

### 一、界面UI使用QT Designer设计, 通过pyuic转换成python文件

```
pyuic5 example.ui -o example.py
```

### 二、windows工具使用pyinstaller打包,打包命令:

```
pyinstaller -F main.py
pyinstaller -F main.spec --clean
```

## 可商用替代品 pySide

* 用法大致与pyQt相同，教程参考```https://zetcode.com/gui/pysidetutorial/```

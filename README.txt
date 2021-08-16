# Gomate
Gomate is an advanced anlysis and eraser plugin of IDA 7.5+ for Go 1.16 executables.
Gomate 是一个为 Go 1.16 量身定制的分析关键和擦除关键信息的 IDA 7.5+ 插件.

Gomate works with IDApython 3.9.
Gomate 使用 IDApython 3.9.

## Installation / 安装

Just download all files to Your Computer.
将仓库所有文件下载到你的电脑上.

## Usage / 使用
Use IDA to analyse aim Go executables. When IDA is idle, just click  the "script file" menu. And select the go_eraser.py.
先使用 IDA 分析目标 Go 程序。当 IDA 分析完毕， 使用 IDA 菜单中的脚本文件功能，选择 go_eraser.py.

## Info / 提示
Some Python Class of this tools can execute "eraser" function which is used to erase some trival data structures to promote difficulty of reverse engineer. If you just want to analyse Go executables, you should delete all invocations of "eraser()" in go_eraser.py.

工具中一些 Python 类提供了 "eraser" 方法，方法默认将在 go_eraser.py 调用用以删除对于运行来说不重要的数据结构来提升逆向难度。如果你不想要擦除这些数据结构，你需要删除 go_eraser.py 中所有有关 eraser的调用。
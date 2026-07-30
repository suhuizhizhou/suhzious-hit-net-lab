# suhzious-hit-net-lab
简单教学型的网络协议栈实现

## 运行

```powershell
.\build\main.exe <virtual-ip>
```

虚拟 IP 必须未被占用，并且与选中的物理网卡处于同一子网。示例程序提供两个回显服务：

- UDP `60000`
- TCP `60001`

TCP 当前实现被动打开、三次握手、按序数据收发、ACK、RST 和 FIN 关闭。暂未实现主动连接、乱序重组、滑动窗口、拥塞控制和超时重传。

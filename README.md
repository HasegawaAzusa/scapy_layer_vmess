# Scapy Layer: VMess

这是一个自写的可以利用scapy机制解析VMess流量的代码。

由于scapy重建数据没有那么灵活，于是只能从另一方面解决bug，目前这个版本勉强可以使用，但是缺少了部分加解密方式。

> 目前只支持 AES-128-GCM。

用法示例

```python
from uuid import UUID
import vmess
from scapy.all import *

vmess_id = UUID("f3a5cae3-6bd2-40d1-b13b-2cc3d87af2c7")
target_port = 40086
vmess.VMessID.set(vmess_id)
vmess.bind(target_port)

packets = sniff(offline="challenge.pcapng", session=TCPSession)
with open('rst.txt', 'w', encoding='utf-8') as f:
    for i, pkt in enumerate(packets):
        pkt: Packet
        f.write(pkt.show(dump=True))
```

其中 `vmess.VMessID.set` 是绑定 VMess 密钥，即 uuid。

而 `vmess.bind` 是为了绑定代理服务器端口。（理论上绑定所有TCP流量也可以，只是目前还未完善该项目）


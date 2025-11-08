
eBPFを使ってGo言語のプログラムに変更を加えずOpenTelemetryのトレースを送信する

<img width="1284" height="699" alt="image" src="https://github.com/user-attachments/assets/4bf62766-9467-4681-b089-b5659db19ff5" />


## 起動方法

```
# VMを起動
limactl create --name go-auto-instrument-ebpf ./lima.yaml
limactl start go-auto-instrument-ebpf

go generate
go build
sudo ./go-auto-instrument-ebpf <対象のバイナリ>
```


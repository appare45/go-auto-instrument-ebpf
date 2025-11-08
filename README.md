
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
2025/11/07 18:14:42 Function net/http.serverHandler.ServeHTTP executed Protocol: 1.1 Host localhost:8080 Duration: 104 ms
2025/11/07 18:14:42 Function net/http.serverHandler.ServeHTTP executed Protocol: 1.1 Host localhost:8080 Duration: 102 ms
2025/11/07 18:14:43 Function net/http.serverHandler.ServeHTTP executed Protocol: 1.1 Host localhost:8080 Duration: 102 ms
```


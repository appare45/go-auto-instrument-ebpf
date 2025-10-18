package main

//go:generate go tool bpf2go -target=$GOARCH -tags linux tracer tracer.c --  -I/usr/include/aarch64-linux-gnu

package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func probeFunc(ex *link.Executable, start *ebpf.Program, end *ebpf.Program, startAddr uint64, endAddrs []uint64) ([]link.Link, error) {
	probes := make([]link.Link, 0, len(endAddrs)+1)
	up, err := ex.Uprobe("", start, &link.UprobeOptions{Address: startAddr})
	if err != nil {
		return nil, err
	}
	probes = append(probes, up)

	for _, retOffset := range endAddrs {
		uretp, err := ex.Uprobe("", end, &link.UprobeOptions{Address: retOffset})
		if err != nil {
			return nil, err
		}
		probes = append(probes, uretp)
	}
	return probes, nil
}

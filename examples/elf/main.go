package main

import (
	"debug/elf"
	"log"
	"os"

	elffunction "github.com/appare45/go-auto-instrument-ebpf/elffunction"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <binary> <symbol>", os.Args[0])
	}

	binPath := os.Args[1]

	fd, err := os.Open(binPath)
	if err != nil {
		log.Fatalf("opening binary file: %s", err)
	}

	elfFile, err := elf.NewFile(fd)
	if err != nil {
		log.Fatalf("parsing ELF file: %s", err)
	}

	targetSymbolName := os.Args[2]
	if targetSymbolName == "" {
		log.Fatalf("symbol name is required")
	}

	analyzer, err := elffunction.NewAnalyzer(elfFile)
	if err != nil {
		log.Fatalf("failed to initialize analyzer: %s", err)
	}

	offset, retOffsets, err := analyzer.Get(targetSymbolName)
	if err != nil {
		log.Fatalf("failed to get offsets for symbol %s: %s", targetSymbolName, err)
	}

	log.Printf("Symbol: %s, File Offset: 0x%X", targetSymbolName, offset)
	for _, retAddr := range retOffsets {
		log.Printf("Possible RET instruction at File Offset: 0x%X", retAddr)
	}
}

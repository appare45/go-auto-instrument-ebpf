package main

import (
	"debug/elf"
	"log"
	"os"
	"slices"
	"sort"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <binary>", os.Args[0])
	}

	binPath := os.Args[1]

	fd, err := os.Open(binPath)
	if err != nil {
		log.Fatalf("opening binary file: %s", err)
	}

	elf_file, err := elf.NewFile(fd)
	if err != nil {
		log.Fatalf("parsing ELF file: %s", err)
	}

	symbols, err := elf_file.Symbols()
	if err != nil {
		log.Fatalf("reading symbols from ELF file: %s", err)
	}

	targetSymbolName := os.Args[2]
	if targetSymbolName == "" {
		log.Fatalf("symbol name is required")
	}

	symbolsAddress := make(map[string]uint64, 0)

	// 事前にプログラムヘッダからアドレス範囲とオフセットを取得しておく
	pheaders := make(map[int]elf.ProgHeader, 0)
	pheader_addresses := make([]int, 0)
	for _, ph := range elf_file.Progs {
		if ph.Type != elf.PT_LOAD || (ph.Flags&elf.PF_X) == 0 {
			continue
		}
		va := int(ph.Vaddr)
		pheaders[va] = ph.ProgHeader
		pheader_addresses = append(pheader_addresses, va)
	}
	slices.Sort(pheader_addresses)

	var targetSymbolAddress uint64

	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Name == targetSymbolName {
			vaIndex := sort.SearchInts(pheader_addresses, int(sym.Value))
			if vaIndex == 0 {
				log.Fatalf("symbol %s not in any program header", targetSymbolName)
			}

			va := pheader_addresses[vaIndex-1]
			ph := pheaders[va]
			if !(int(sym.Value) < va+int(ph.Memsz)) {
				log.Fatalf("symbol %s not in any program header", targetSymbolName)
			}
			// https://stackoverflow.com/questions/40237321/find-functions-start-offset-in-elf/40249502#40249502
			targetSymbolAddress = ph.Off + sym.Value - uint64(va)
			symbolsAddress[sym.Name] = targetSymbolAddress
			break
		}
	}
	log.Printf("Symbol: %s, File Offset: 0x%X", targetSymbolName, targetSymbolAddress)
}

package main

import (
	"debug/elf"
	"errors"
	"io"
	"log"
	"os"
	"slices"
	"sort"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	// https://developer.arm.com/documentation/102374/0103/Instruction-sets-in-the-Arm-architecture?lang=en
	// 32-bitなので4バイト
	arm64RetInstructionSize = 4
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

	symbolsOffsets := make(map[string]uint64, 0)

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

	var targetSymbolOffset uint64
	possibleResutrnAddresses := make([]uint64, 0)
	textSection := elf_file.Section(".text")

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
			targetSymbolOffset = ph.Off + sym.Value - uint64(va)
			symbolsOffsets[sym.Name] = targetSymbolOffset
			buf := make([]byte, sym.Size)
			readbytes, err := textSection.ReadAt(buf, int64(sym.Value-textSection.Addr))
			// sym.Sizeとreadbytesが一致しないことはあり得るはずなので、EOF以外のエラーのみ処理する
			if err != nil && !errors.Is(err, io.EOF) {
				log.Fatalf("reading symbol %s bytes failed: %s", sym.Name, err)
			}

			if readbytes == 0 {
				log.Fatalf("symbol %s has zero size, skipping", sym.Name)
			}

			readBuf := buf[:readbytes]

			for i := 0; i < len(readBuf); i += arm64RetInstructionSize {
				instruction, err := arm64asm.Decode(readBuf[i:])
				if err != nil {
					log.Printf("decoding instruction failed at offset 0x%X: %s", targetSymbolOffset+uint64(i), err)
					continue
				}
				if instruction.Op == arm64asm.RET {
					possibleResutrnAddresses = append(possibleResutrnAddresses, targetSymbolOffset+uint64(i))
				}
			}
			break
		}
	}
	log.Printf("Symbol: %s, File Offset: 0x%X", targetSymbolName, targetSymbolOffset)

	for _, retAddr := range possibleResutrnAddresses {
		log.Printf("Possible RET instruction at File Offset: 0x%X", retAddr)
	}
}

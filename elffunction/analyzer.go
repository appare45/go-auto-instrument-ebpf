package elf

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"io"
	"slices"
	"sort"

	"golang.org/x/arch/arm64/arm64asm"
)

// 関数情報
type FuncInfo struct {
	Value  uint64
	Size   uint64
	Memsz  uint64
	Offset uint64
}

// ELF解析構造体
type ElfFunctionAnalyzer struct {
	// 関数名と関数情報のマップ
	FuncMap     map[string]FuncInfo
	TextSection *elf.Section
	Dwarf       *dwarf.Data
}

// ELFファイルから初期化
func NewAnalyzer(elfFile *elf.File) (*ElfFunctionAnalyzer, error) {
	funcMap := make(map[string]FuncInfo)
	pheaders := make(map[int]elf.ProgHeader)
	pheaderAddrs := make([]int, 0)

	for _, ph := range elfFile.Progs {
		if ph.Type != elf.PT_LOAD || (ph.Flags&elf.PF_X) == 0 {
			continue
		}
		va := int(ph.Vaddr)
		pheaders[va] = ph.ProgHeader
		pheaderAddrs = append(pheaderAddrs, va)
	}
	slices.Sort(pheaderAddrs)

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, err
	}

	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		vaIndex := sort.SearchInts(pheaderAddrs, int(sym.Value))
		if vaIndex == 0 {
			continue
		}
		va := pheaderAddrs[vaIndex-1]
		ph := pheaders[va]
		if !(int(sym.Value) < va+int(ph.Memsz)) {
			continue
		}
		offset := ph.Off + sym.Value - uint64(va)
		funcMap[sym.Name] = FuncInfo{
			Value:  sym.Value,
			Size:   sym.Size,
			Memsz:  ph.Memsz,
			Offset: offset,
		}
	}

	dwarf, err := elfFile.DWARF()
	if err != nil {
		return nil, err
	}

	return &ElfFunctionAnalyzer{
		FuncMap:     funcMap,
		TextSection: elfFile.Section(".text"),
		Dwarf:       dwarf,
	}, nil
}

func (e ElfFunctionAnalyzer) dwarfTypeByName(name string) (dwarf.Type, error) {
	for {
		rdr := e.Dwarf.Reader()
		for {
			entry, err := rdr.Next()
			if err != nil {
				return nil, err
			}
			if entry == nil {
				break
			}
			if entry.Tag == dwarf.TagTypedef {
				nameAttr := entry.AttrField(dwarf.AttrName)
				if nameAttr != nil && nameAttr.Val == name {
					typeOffset := entry.Val(dwarf.AttrType).(dwarf.Offset)
					t, err := e.Dwarf.Type(typeOffset)
					if err != nil {
						return nil, err
					}
					return t, nil
				}
			}
		}
	}
}

func (e ElfFunctionAnalyzer) StructFieldOffset(name string, fieldName string) (int64, error) {
	t, err := e.dwarfTypeByName(name)
	if err != nil {
		return 0, err
	}
	if structType, ok := t.(*dwarf.StructType); ok {
		for _, field := range structType.Field {
			if field.Name == fieldName {
				return field.ByteOffset, nil
			}
		}
		return 0, errors.New("field not found: " + fieldName)
	}
	return 0, errors.New("type is not a struct: " + name)
}

// 関数名からFileOffsetとRET命令のFileOffsetリストを取得
func (e *ElfFunctionAnalyzer) Get(funcName string) (uint64, []uint64, error) {
	info, ok := e.FuncMap[funcName]
	if !ok {
		return 0, nil, errors.New("function not found")
	}

	buf := make([]byte, info.Size)
	readbytes, err := e.TextSection.ReadAt(buf, int64(info.Value-e.TextSection.Addr))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, nil, err
	}
	if readbytes == 0 {
		return 0, nil, errors.New("function size is zero")
	}
	readBuf := buf[:readbytes]

	retOffsets := make([]uint64, 0)
	const arm64RetInstructionSize = 4
	for i := 0; i < len(readBuf); i += arm64RetInstructionSize {
		instruction, err := arm64asm.Decode(readBuf[i:])
		if err != nil {
			continue
		}
		if instruction.Op == arm64asm.RET {
			retOffsets = append(retOffsets, info.Offset+uint64(i))
		}
	}

	return info.Offset, retOffsets, nil
}

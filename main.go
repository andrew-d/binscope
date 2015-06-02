package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	flag "github.com/ogier/pflag"
)

const (
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x0100
	IMAGE_DLLCHARACTERISTICS_NO_SEH       = 0x0400

	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

	IMAGE_SUBSYSTEM_NATIVE      = 1
	IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
	IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

	IMAGE_SCN_MEM_SHARED = 0x10000000
	IMAGE_SCN_MEM_READ   = 0x40000000
	IMAGE_SCN_MEM_WRITE  = 0x80000000
)

type ImageLoadConfigDirectory32 struct {
	Size                          uint32
	TimeDateStamp                 uint32
	MajorVersion                  uint16
	MinorVersion                  uint16
	GlobalFlagsClear              uint32
	GlobalFlagsSet                uint32
	CriticalSectionDefaultTimeout uint32
	DeCommitFreeBlockThreshold    uint32
	DeCommitTotalFreeThreshold    uint32
	LockPrefixTable               uint32
	MaximumAllocationSize         uint32
	VirtualMemoryThreshold        uint32
	ProcessHeapFlags              uint32
	ProcessAffinityMask           uint32
	CSDVersion                    uint16
	Reserved1                     uint16
	EditList                      uint32
	SecurityCookie                uint32
	SEHandlerTable                uint32
	SEHandlerCount                uint32
}

type ImageLoadConfigDirectory64 struct {
	Size                          uint32
	TimeDateStamp                 uint32
	MajorVersion                  uint16
	MinorVersion                  uint16
	GlobalFlagsClear              uint32
	GlobalFlagsSet                uint32
	CriticalSectionDefaultTimeout uint32
	DeCommitFreeBlockThreshold    uint64
	DeCommitTotalFreeThreshold    uint64
	LockPrefixTable               uint64
	MaximumAllocationSize         uint64
	VirtualMemoryThreshold        uint64
	ProcessAffinityMask           uint64
	ProcessHeapFlags              uint32
	CSDVersion                    uint16
	Reserved1                     uint16
	EditList                      uint64
	SecurityCookie                uint64
	SEHandlerTable                uint64
	SEHandlerCount                uint64
}

var (
	sizeofImageLoadConfigDirectory32 = uint16(binary.Size(ImageLoadConfigDirectory32{}))
	sizeofImageLoadConfigDirectory64 = uint16(binary.Size(ImageLoadConfigDirectory64{}))

	flagVerbose bool
)

func init() {
	flag.BoolVarP(&flagVerbose, "verbose", "v", false, "be verbose")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: binscope [options] <file1>...\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	for _, fname := range flag.Args() {
		if flagVerbose {
			log.Println("Checking file:", fname)
		}

		if err := check(fname); err != nil {
			log.Printf("Error checking file:", err)
		}
	}
}

func check(fname string) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	pefile, err := pe.NewFile(f)
	if err != nil {
		return err
	}

	dch := getDllCharacteristics(pefile)
	subsystem := getSubsystem(pefile)

	if flagVerbose {
		log.Printf("   Machine = 0x%04d\n", pefile.Machine)
		log.Printf("   Subsystem = %d\n", subsystem)
		log.Printf("   DllCharacteristics = 0x%04x\n", dch)
	}

	// Device drivers always have these flags set.
	if subsystem != IMAGE_SUBSYSTEM_NATIVE {
		if dch&IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0 {
			fmt.Printf("%s:does not have NXCOMPAT bit set\n", fname)
		}
		if dch&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
			fmt.Printf("%s:does not have DYNAMICBASE bit set\n", fname)
		}
	}

	// Check for the /GS flag
	dir, err := readImageLoadConfigDirectory(pefile)
	if err != nil {
		return err
	}
	if dir != nil {
		var securityCookie uint64
		switch imdir := dir.(type) {
		case *ImageLoadConfigDirectory32:
			securityCookie = uint64(imdir.SecurityCookie)
		case *ImageLoadConfigDirectory64:
			securityCookie = imdir.SecurityCookie
		default:
			panic("bad load config directory type")
		}

		if flagVerbose {
			log.Printf("   SecurityCookie = 0x%x", securityCookie)
		}
		if securityCookie == 0 {
			fmt.Printf("%s:does not use security cookies\n", fname)
		}

		// Check for SAFESEH on Windows x86 only
		if pefile.Machine == pe.IMAGE_FILE_MACHINE_I386 {
			if dch&IMAGE_DLLCHARACTERISTICS_NO_SEH == 0 {
				handlerTable := dir.(*ImageLoadConfigDirectory32).SEHandlerTable
				handlerCount := dir.(*ImageLoadConfigDirectory32).SEHandlerTable

				if handlerTable == 0 {
					fmt.Printf("%s:does not use SAFESEH\n", fname)
				}

				if flagVerbose {
					log.Printf("   SEHandlerTable = 0x%x\n", handlerTable)
					log.Printf("   SEHandlerCount = 0x%x\n", handlerCount)
				}
			} else if flagVerbose {
				log.Println("   Skipping SAFESEH check because image has NO_SEH bit set")
			}
		} else if flagVerbose {
			log.Println("   Skipping SAFESEH check on non-x86 file")
		}
	}

	// Check for R/W shared image sections
	var rwSharedFlags uint32 = IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
	for _, section := range pefile.Sections {
		if section.Characteristics&rwSharedFlags == rwSharedFlags {
			fmt.Printf("%s:has a R/W shared section named %s\n", fname, section.Name)
		}
	}

	return nil
}

func getDllCharacteristics(pefile *pe.File) uint16 {
	switch hdr := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return hdr.DllCharacteristics
	case *pe.OptionalHeader64:
		return hdr.DllCharacteristics
	default:
		panic("unknown optional header")
	}
}

func getSubsystem(pefile *pe.File) uint16 {
	switch hdr := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return hdr.Subsystem
	case *pe.OptionalHeader64:
		return hdr.Subsystem
	default:
		panic("unknown optional header")
	}
}

func getDataDirectory(pefile *pe.File, index int) pe.DataDirectory {
	if index > 15 || index < 0 {
		panic("bad index")
	}

	switch hdr := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return hdr.DataDirectory[index]
	case *pe.OptionalHeader64:
		return hdr.DataDirectory[index]
	default:
		panic("unknown optional header")
	}
}

func readImageLoadConfigDirectory(pefile *pe.File) (interface{}, error) {
	dir := getDataDirectory(pefile, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
	if dir.VirtualAddress == 0 {
		return nil, nil
	}

	// Allocate enough memory for the section.
	if pefile.Machine != pe.IMAGE_FILE_MACHINE_I386 && pefile.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil, fmt.Errorf("unknown machine type: %04x", pefile.Machine)
	}

	// Now, we have the directory's virtual address.  To get the file offset,
	// we need to loop through all sections to find the containing one.
	var sr io.ReadSeeker
	for _, section := range pefile.Sections {
		if dir.VirtualAddress < section.VirtualAddress ||
			dir.VirtualAddress >= (section.VirtualAddress+section.Size) {
			continue
		}

		sr = section.Open()

		// Seek to the right place
		offset := int64(dir.VirtualAddress - section.VirtualAddress)
		sr.Seek(offset, os.SEEK_SET)
		break
	}

	if sr == nil {
		return nil, fmt.Errorf("did not find data directory containing VA 0x%08x", dir.VirtualAddress)
	}

	// Convert into the appropriate format.
	if pefile.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		var ret ImageLoadConfigDirectory32

		if err := binary.Read(sr, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}

		return &ret, nil
	} else {
		var ret ImageLoadConfigDirectory64

		if err := binary.Read(sr, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}

		return &ret, nil
	}
}

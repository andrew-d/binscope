# binscope

`binscope` is a simple tool that checks a Windows PE file for some basic
security issues, including:

- No `/DYNAMICBASE` flag (i.e. no support for ASLR).
- No `/NXCOMPAT` flag (i.e. no support for DEP).
- No `/GS` flag (i.e. no stack cookies) - **note: not currently working**
- No `/SAFESEH` flag in x86 binaries
- Having any PE sections that are shared and are Read/Write.

There are some test binaries in the `test_binaries` subfolder that demonstrate
the output for various vulnerabilities.

## Example Output

```
$ ./binscope ./test_binaries/x86/*.exe
./test_binaries/x86/CompileFlags-no-DYNAMICBASE.exe:does not have DYNAMICBASE bit set
./test_binaries/x86/CompileFlags-no-NXCOMPAT.exe:does not have NXCOMPAT bit set
./test_binaries/x86/CompileFlags-no-SAFESEH.exe:does not use SAFESEH
```

## Installation

You can either compile the code manually:

    git clone https://github.com/andrew-d/binscope.git
    cd binscope
    go build -v .

Or you can obtain a [pre-compiled release](https://github.com/andrew-d/binscope/releases).

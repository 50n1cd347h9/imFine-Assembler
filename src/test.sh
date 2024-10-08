#!/bin/sh

# assemble
./zig-out/bin/imFine-Assembler ./src/executable/label.asm

# execute binary
./src/imFineVM  ./src/executable/label.bin  2>&1 | awk 'NR == 1 { print $0 }'

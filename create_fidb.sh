#!/bin/bash

$GHIDRA_INSTALL_DIR/support/analyzeHeadless ./libc_fidb MyLibcFIDB \
  -import ./libc \
  -processor x86:LE:32:default \
  -cspec gcc \
  -recursive


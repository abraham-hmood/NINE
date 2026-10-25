#!/usr/bin/env sh
# Rebuild the built-in NINE x86-64 smoke test.
#
# Requires clang and LLD. The program is freestanding: no libc, no dynamic
# loader, no PT_TLS. It only uses mov/xor/lea/syscall, so it exercises the
# instruction subset NINE's interpreter and JIT already implement.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
clang=${CLANG:-clang}

"$clang" --target=x86_64-linux-gnu \
    -nostdlib -static -fno-pic -fno-stack-protector \
    -fuse-ld=lld -Wl,-e,_start -Wl,--build-id=none -O2 \
    "$here/hello.c" -o "$root/app/src/main/assets/programs/hello-x86_64"

echo "built $root/app/src/main/assets/programs/hello-x86_64"

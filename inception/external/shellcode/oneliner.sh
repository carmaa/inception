#!/bin/bash
hexdump $1 | sed -E 's/^[a-f0-9]+ ? ?//' | sed -E 's/\|.*\|//' | tr -d '\n' | sed -E 's/ +/\\x/g' | sed -E 's/\\x$/\n/' | sed -E 's/^/\\x/' 
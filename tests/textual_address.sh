#!/bin/bash

( echo "$1" | xxd -r -p | /usr/bin/crc32 /dev/stdin; echo -n "$1" ) |
  xxd -r -p | base32 | tr A-Z a-z |
  tr -d = | fold -w5 | paste -sd'-' -


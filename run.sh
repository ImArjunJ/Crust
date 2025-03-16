#!/bin/bash
set -e

#LD_PRELOAD=./build/libcrust.so ./build/test_program
#LD_PRELOAD=./build/libcrust.so ./build/test_overflow 
#LD_PRELOAD=./build/libcrust.so ./build/test_stress
#LD_PRELOAD=./build/libcrust.so ./build/test_uaf
#LD_PRELOAD=./build/libcrust.so ./build/test_double_free
LD_PRELOAD=./build/libcrust.so ./build/test_invalid_free
#!/bin/bash
set -e

LD_PRELOAD=./build/libcrust.so ./build/test_program
#LD_PRELOAD=./build/libcrust.so ./build/test_overflow 
#LD_PRELOAD=./build/libcrust.so ./build/test_stress
#LD_PRELOAD=./build/libcrust.so ./build/test_uaf
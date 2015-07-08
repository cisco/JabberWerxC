#!/bin/bash
if [ ! -d "build" ]; then
    mkdir build
fi
cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -Ddo_coverage=ON && make all test && echo Report: file://`pwd`/coverage/index.html

#!/bin/sh

cd tests
pip install --user -r requirements.txt

if [ ! -d googletest ]; then
  git clone https://github.com/google/googletest
fi

if [ ! -d gtest ]; then
  ./googletest/googletest/scripts/fuse_gtest_files.py .
fi

cd ..

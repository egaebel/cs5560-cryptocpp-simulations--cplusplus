#/bin/sh

#Add correct folder to C++ includes path
export CPLUS_INCLUDE_PATH="../cryptopp/"

#Compile some file using cryptopp
g++ -g3 -ggdb -O0 -Wall -Wno-unused -o $1-test $1 -lcryptopp
./$1-test
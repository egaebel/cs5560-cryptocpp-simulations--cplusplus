all: export CPLUS_INCLUDE_PATH = cryptopp
all:
	g++ -g3 -ggdb -O0 -Wall -Wno-unused -o sim-test sim.cpp -lcryptopp -static -pthread


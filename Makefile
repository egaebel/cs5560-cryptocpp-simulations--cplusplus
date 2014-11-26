all: export CPLUS_INCLUDE_PATH = cryptopp
all:
	g++ -Wall -Wno-unused -std=c++0x -o sim-test sim.cpp -lcryptopp -static -pthread

debug: export CPLUS_INCLUDE_PATH = cryptopp
debug:
	g++ -g3 -ggdb -O0 -Wall -Wno-unused -std=c++0x -o sim-test sim.cpp -lcryptopp -static -pthread

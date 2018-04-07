.DEFAULT_GOAL := compile

.PHONY: compile
compile:
	g++ -std=c++14 -Wall -lpcap -pthread *.cc *.h -o zkdump

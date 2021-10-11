.PHONY: client server

all : client client2 server
client: src/client.cpp
	g++ $< -o client -pthread -lssl -lcrypto

server: src/server.cpp
	g++ $< -o server -pthread -lssl -lcrypto
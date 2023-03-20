
#编译并运行服务器端
runs:
	g++ server.cpp des.cpp -o server -Wno-write-strings
	./server


#编译并运行客户端
runc:
	g++ client.cpp des.cpp -o client  -Wno-write-strings
	./client
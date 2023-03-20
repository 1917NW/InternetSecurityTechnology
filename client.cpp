#include<iostream>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include "secretchat.h"
using namespace std;
int main(){
    
	int nConnectSocket, nLength;
	struct sockaddr_in sDestAddr;
	char strIpAddr[16];
	cout<<"请输入所连接的服务所在的ip地址:\n";
	cin>>strIpAddr;
	int port;
	cout<<"请输入所连接的服务所占用的端口:\n";
	cin>>port;
    //分配套接字
	if ((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
		perror("Socket");
		exit(errno);
	}
    
    //填充服务器端地址信息
	sDestAddr.sin_family = AF_INET;
	sDestAddr.sin_port = htons(port);
	sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr);
	

    //向服务器发出连接请求
	if (connect(nConnectSocket, (struct sockaddr *) &sDestAddr, sizeof(sDestAddr)) != 0) 
	{
		perror("Connect ");
		exit(errno);
	}
	else
	{
		printf("Connect Success!  \nBegin to chat...\n");
		SecretChat(nConnectSocket,strIpAddr,"benbenmi");	
    }


    close(nConnectSocket);	

}
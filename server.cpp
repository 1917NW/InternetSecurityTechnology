#include<iostream>
#include<string.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/socket.h>

#include "secretchat.h"
#include "des.h"
using namespace std;
int main(){
    int nListenSocket,nAcceptSocket;
    struct sockaddr_in sLocalAddr,sRemoteAddr;
    socklen_t nLength;
    
    //分配套接字
    nListenSocket = socket(PF_INET,SOCK_STREAM,0);
    //填充服务器端地址
    memset(&sLocalAddr,0,sizeof(sLocalAddr));
    sLocalAddr.sin_family=AF_INET;
    sLocalAddr.sin_addr.s_addr=htonl(INADDR_ANY);
    char port[16];
    cout<<"请输入开启此服务所占用的端口号: \n";
    cin>>port;
    sLocalAddr.sin_port=htons(atoi(port));

    
    
    //给服务器监听套接字分配地址
    if(bind(nListenSocket,(struct sockaddr*)&sLocalAddr,sizeof(struct sockaddr))==-1)
    {
        perror("bind wrong");
        exit(1);
    }
   
    if(listen(nListenSocket,5)==1)
    {
        perror("listen wrong");
        exit(1);
    }
    printf("listening...");
    nAcceptSocket = accept(nListenSocket,(struct sockaddr*)&sRemoteAddr,&nLength);
    close(nListenSocket);
    printf("server: got connection from %s, port %d, socket %d\n",inet_ntoa(sRemoteAddr.sin_addr),ntohs(sRemoteAddr.sin_port), nAcceptSocket);
	SecretChat(nAcceptSocket,inet_ntoa(sRemoteAddr.sin_addr),"benbenmi");		

    
    close(nAcceptSocket);
    
    return 0;
	
}


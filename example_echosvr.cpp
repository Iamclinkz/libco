/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/



#include "co_routine.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <stack>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#ifdef __FreeBSD__
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#endif

using namespace std;

//任务结构，内部有一个完整的co的运行时信息 + 希望这个co监听的fd
struct task_t
{
	stCoRoutine_t *co;
	int fd;
};

//存储本进程内的当前空闲的co
//当co发现自己没事做（fd == -1）时，会将自己push进来
//当处理新连接co有Accept时，会从这里面找有没有空闲的co
//注意这里stack不需要设计成线程安全的，因为从头到尾我们都是单进程，单线程
static stack<task_t*> g_readwrite;

//处理新连接co监听的服务器的fd
static int g_listen_fd = -1;

//将fd设置成非阻塞模式
static int SetNonBlock(int iSock)
{
    int iFlags;

    iFlags = fcntl(iSock, F_GETFL, 0);
	//非阻塞模式
    iFlags |= O_NONBLOCK;
	//与O_NONBLOCK具有相同的功能。在某些系统中，这两个常量可能有所不同，因此这里同时设置它们以确保兼容性。
    iFlags |= O_NDELAY;
	//使用flag，设置套接字的模式
    int ret = fcntl(iSock, F_SETFL, iFlags);
    return ret;
}

//子co的主循环函数，用于监听、处理一个已经accept的，跟客户端连接的fd
static void *readwrite_routine( void *arg )
{
	//hook系统调用，使用co友好版的poll，read等函数
	co_enable_hook_sys();

	task_t *co = (task_t*)arg;
	char buf[ 1024 * 16 ];
	for(;;)
	{
		if( -1 == co->fd )
		{
			//如果当前自己没有fd可读，那么先把自己放到等待stack中，让出cpu，等待主co调度
			g_readwrite.push( co );
			co_yield_ct();

			//代码执行到这里，已经让出cpu，又切换回来了，可以继续执行
			continue;
		}

		//代码执行到这里，自己已经被分配了监听一个fd的任务
		int fd = co->fd;
		co->fd = -1;

		for(;;)
		{
			//这里的pollfd只是用于函数调用时，传递poll相关的信息，底层还是使用epoll的
			struct pollfd pf = { 0 };
			pf.fd = fd;
			//fd可读/错误/挂起（对端关闭连接）
			pf.events = (POLLIN|POLLERR|POLLHUP);
			//等待来自客户端的消息，将自己监听的fd，挂载到全局保存的epoll结构体中
			//注意，执行结束后，已经让出cpu了
			co_poll( co_get_epoll_ct(),&pf,1,1000);

			//代码执行到这里，可能是因为有新连接连入，可能是超时1s，总之读一下试试。这里是非阻塞读，肯定没问题
			int ret = read( fd,buf,sizeof(buf) );
			if( ret > 0 )
			{
				//如果确实读到了内容，那么将读到的内容再写回去
				ret = write( fd,buf,ret );
			}
			if( ret > 0 || ( -1 == ret && EAGAIN == errno ) )
			{
				//如果失败，并且errno是EAGAIN，那么不重试，直接下一轮
				continue;
			}

			//如果是其他的错误，直接close fd，然后再等待处理新连接co派任务
			close( fd );
			break;
		}

	}
	return 0;
}

int co_accept(int fd, struct sockaddr *addr, socklen_t *len );

//处理新连接co的主循环，监听服务器fd，accept并且传给子co处理
static void *accept_routine( void * )
{
	co_enable_hook_sys();
	printf("accept_routine\n");
	fflush(stdout);
	for(;;)
	{
		//printf("pid %ld g_readwrite.size %ld\n",getpid(),g_readwrite.size());
		if( g_readwrite.empty() )
		{
			//如果当前没有空闲的子co，那么处理新连接co睡眠等待1s
			printf("empty\n"); //sleep
			struct pollfd pf = { 0 };
			pf.fd = -1;
			poll( &pf,1,1000);

			//代码执行到这里，已经睡眠结束了，再到下一轮看看有没有空闲的子co
			continue;
		}
		struct sockaddr_in addr; //maybe sockaddr_un;
		memset( &addr,0,sizeof(addr) );
		socklen_t len = sizeof(addr);

		//试着accept一下，这里不会让本co让出cpu
		int fd = co_accept(g_listen_fd, (struct sockaddr *)&addr, &len);
		if( fd < 0 )
		{
			//如果没有客户端试图连接（accept失败）
			//那么继续poll服务器的fd即可。
			struct pollfd pf = { 0 };
			pf.fd = g_listen_fd;
			pf.events = (POLLIN|POLLERR|POLLHUP);
			co_poll( co_get_epoll_ct(),&pf,1,1000 );
			continue;
		}
		if( g_readwrite.empty() )
		{
			//感觉这里应该不会执行到吧。。
			close( fd );
			continue;
		}

		//设置非阻塞，取出一个空闲子co，服务这个连接即可。
		SetNonBlock( fd );
		task_t *co = g_readwrite.top();
		co->fd = fd;
		g_readwrite.pop();
		//唤醒子co，服务这个新连接
		co_resume( co->co );
	}
	return 0;
}

static void SetAddr(const char *pszIP,const unsigned short shPort,struct sockaddr_in &addr)
{
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(shPort);
	int nIP = 0;
	if( !pszIP || '\0' == *pszIP   
	    || 0 == strcmp(pszIP,"0") || 0 == strcmp(pszIP,"0.0.0.0") 
		|| 0 == strcmp(pszIP,"*") 
	  )
	{
		nIP = htonl(INADDR_ANY);
	}
	else
	{
		nIP = inet_addr(pszIP);
	}
	addr.sin_addr.s_addr = nIP;

}

static int CreateTcpSocket(const unsigned short shPort /* = 0 */,const char *pszIP /* = "*" */,bool bReuse /* = false */)
{
	int fd = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
	if( fd >= 0 )
	{
		if(shPort != 0)
		{
			if(bReuse)
			{
				int nReuseAddr = 1;
				setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&nReuseAddr,sizeof(nReuseAddr));
			}
			struct sockaddr_in addr ;
			SetAddr(pszIP,shPort,addr);
			int ret = bind(fd,(struct sockaddr*)&addr,sizeof(addr));
			if( ret != 0)
			{
				close(fd);
				return -1;
			}
		}
	}
	return fd;
}


int main(int argc,char *argv[])
{
	if(argc<5){
		printf("Usage:\n"
               "example_echosvr [IP] [PORT] [TASK_COUNT] [PROCESS_COUNT]\n"
               "example_echosvr [IP] [PORT] [TASK_COUNT] [PROCESS_COUNT] -d   # daemonize mode\n");
		return -1;
	}
	//监听ip，端口，开子co个数，开进程个数，是否等待结束
	const char *ip = argv[1];
	int port = atoi( argv[2] );
	int cnt = atoi( argv[3] );
	int proccnt = atoi( argv[4] );
	bool deamonize = argc >= 6 && strcmp(argv[5], "-d") == 0;

	//创建tcp socket
	g_listen_fd = CreateTcpSocket( port,ip,true );
	listen( g_listen_fd,1024 );
	if(g_listen_fd==-1){
		printf("Port %d is in use\n", port);
		return -1;
	}
	printf("listen %d %s:%d\n",g_listen_fd,ip,port);

	SetNonBlock( g_listen_fd );

	for(int k=0;k<proccnt;k++)
	{
		//这里也是学到了。。可以让很多个进程同时监听一个socket。
		//具体操作是先listen一个fd，然后fork出很多个进程，然后很多个进程就可以一起listen同一个socket文件了

		//创建proccnt个进程
		pid_t pid = fork();
		if( pid > 0 )
		{
			continue;
		}
		else if( pid < 0 )
		{
			break;
		}
		for(int i=0;i<cnt;i++)
		{
			task_t * task = (task_t*)calloc( 1,sizeof(task_t) );
			task->fd = -1;
			//每个进程创建cnt个子co，每个子co肯定会因为暂时没有要服务的fd，而直接返回
			co_create( &(task->co),NULL,readwrite_routine,task );
			co_resume( task->co );
		}

		//创建完子co之后，再创建一个处理新连接co，负责accept客户端连接
		stCoRoutine_t *accept_co = NULL;
		co_create( &accept_co,NULL,accept_routine,0 );
		co_resume( accept_co );

		//主进程执行eventLoop
		co_eventloop( co_get_epoll_ct(),0,0 );

		exit(0);
	}
	if(!deamonize) wait(NULL);
	return 0;
}


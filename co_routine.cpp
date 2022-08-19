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
#include "co_routine_inner.h"
#include "co_epoll.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>

#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>

extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
using namespace std;
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env );
struct stCoEpoll_t;

//全局的本线程共享的记录co调用链的结构,随着主协程一起被创建,简称线程env
struct stCoRoutineEnv_t
{
	//保存调用链的栈，libco是一个非对称的co模型，每次调用者（return）调用被调用者（call）的
	//时候，把被调用者压栈，然后iCallStackSize+1，然后从被调用者返回的时候再弹出并且将
	//iCallStackSize-1.每个线程共有一个,记录本线程上运行的协程的执行顺序
	//所以这个pCallStack结构即是保存协程控制块指针类型的数组,用于记录这个调用关系
	//pCallStack[0]即指向主协程
	stCoRoutine_t *pCallStack[ 128 ];
	//当前有几个 co 在运行,可以通过pCallStack[env->iCallStackSize - 1]获取当前正在运行的co的控制块
	int iCallStackSize;

	//用于epoll
	stCoEpoll_t *pEpoll;

	//for copy stack log lastco and nextco
	//当前占有共享栈的co和将要切换运行的co，在不使用共享栈的时候这两个都是空指针
	stCoRoutine_t* pending_co;
	stCoRoutine_t* occupy_co;
};
//int socket(int domain, int type, int protocol);
void co_log_err( const char *fmt,... )
{
}


#if defined( __LIBCO_RDTSCP__) 
static unsigned long long counter(void)
{
	register uint32_t lo, hi;
	register unsigned long long o;
	__asm__ __volatile__ (
			"rdtscp" : "=a"(lo), "=d"(hi)::"%rcx"
			);
	o = hi;
	o <<= 32;
	return (o | lo);

}
static unsigned long long getCpuKhz()
{
	FILE *fp = fopen("/proc/cpuinfo","r");
	if(!fp) return 1;
	char buf[4096] = {0};
	fread(buf,1,sizeof(buf),fp);
	fclose(fp);

	char *lp = strstr(buf,"cpu MHz");
	if(!lp) return 1;
	lp += strlen("cpu MHz");
	while(*lp == ' ' || *lp == '\t' || *lp == ':')
	{
		++lp;
	}

	double mhz = atof(lp);
	unsigned long long u = (unsigned long long)(mhz * 1000);
	return u;
}
#endif

static unsigned long long GetTickMS()
{
#if defined( __LIBCO_RDTSCP__) 
	static uint32_t khz = getCpuKhz();
	return counter() / khz;
#else
	struct timeval now = { 0 };
	gettimeofday( &now,NULL );
	unsigned long long u = now.tv_sec;
	u *= 1000;
	u += now.tv_usec / 1000;
	return u;
#endif
}

/* no longer use
static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
		tid = syscall( SYS_gettid );
		if( -1 == (long)tid )
		{
			tid = pid;
		}
#elif defined( __FreeBSD__ )
		syscall(SYS_thr_self, &tid);
		if( tid < 0 )
		{
			tid = pid;
		}
#else 
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/
template <class T,class TLink>
void RemoveFromLink(T *ap)
{
	TLink *lst = ap->pLink;
	if(!lst) return ;
	assert( lst->head && lst->tail );

	if( ap == lst->head )
	{
		lst->head = ap->pNext;
		if(lst->head)
		{
			lst->head->pPrev = NULL;
		}
	}
	else
	{
		if(ap->pPrev)
		{
			ap->pPrev->pNext = ap->pNext;
		}
	}

	if( ap == lst->tail )
	{
		lst->tail = ap->pPrev;
		if(lst->tail)
		{
			lst->tail->pNext = NULL;
		}
	}
	else
	{
		ap->pNext->pPrev = ap->pPrev;
	}

	ap->pPrev = ap->pNext = NULL;
	ap->pLink = NULL;
}


//apLink是一个双向链表的存放 head 和 tail 的 mark 节点
//ap 是希望插入双向链表的item节点
template <class TNode,class TLink>
void inline AddTail(TLink*apLink,TNode *ap)
{
	if( ap->pLink )
	{
		return ;
	}
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)ap;
		ap->pNext = NULL;
		ap->pPrev = apLink->tail;
		apLink->tail = ap;
	}
	else
	{
		apLink->head = apLink->tail = ap;
		ap->pNext = ap->pPrev = NULL;
	}
	ap->pLink = apLink;
}
template <class TNode,class TLink>
void inline PopHead( TLink*apLink )
{
	if( !apLink->head ) 
	{
		return ;
	}
	TNode *lp = apLink->head;
	if( apLink->head == apLink->tail )
	{
		apLink->head = apLink->tail = NULL;
	}
	else
	{
		apLink->head = apLink->head->pNext;
	}

	lp->pPrev = lp->pNext = NULL;
	lp->pLink = NULL;

	if( apLink->head )
	{
		apLink->head->pPrev = NULL;
	}
}

template <class TNode,class TLink>
void inline Join( TLink*apLink,TLink *apOther )
{
	//printf("apOther %p\n",apOther);
	if( !apOther->head )
	{
		return ;
	}
	TNode *lp = apOther->head;
	while( lp )
	{
		lp->pLink = apLink;
		lp = lp->pNext;
	}
	lp = apOther->head;
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)lp;
		lp->pPrev = apLink->tail;
		apLink->tail = apOther->tail;
	}
	else
	{
		apLink->head = apOther->head;
		apLink->tail = apOther->tail;
	}

	apOther->head = apOther->tail = NULL;
}

/////////////////for copy stack //////////////////////////
//分配一手子栈,并且初始化一个子栈控制块返回
stStackMem_t* co_alloc_stackmem(unsigned int stack_size)
{
	//分配共享栈子栈的控制块
	stStackMem_t* stack_mem = (stStackMem_t*)malloc(sizeof(stStackMem_t));
	stack_mem->occupy_co= NULL;
	stack_mem->stack_size = stack_size;
	//实际上的子栈的分配,可以看出实际上是分配到堆上的
	stack_mem->stack_buffer = (char*)malloc(stack_size);
	stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
	return stack_mem;
}

//从共享栈中分配一手子栈
stShareStack_t* co_alloc_sharestack(int count, int stack_size)
{
	//初始化共享栈控制块结构
	stShareStack_t* share_stack = (stShareStack_t*)malloc(sizeof(stShareStack_t));
	//还没分配的第一个位置设置为 0
	share_stack->alloc_idx = 0;
	//共享栈大小设置
	share_stack->stack_size = stack_size;

	//alloc stack array
	share_stack->count = count;
	//分配 count 个子栈控制块结构大小
	stStackMem_t** stack_array = (stStackMem_t**)calloc(count, sizeof(stStackMem_t*));
	for (int i = 0; i < count; i++)
	{
		stack_array[i] = co_alloc_stackmem(stack_size);
	}
	share_stack->stack_array = stack_array;
	return share_stack;
}

//从共享栈中找到一个没人用的子栈,然后把子栈控制块返回
static stStackMem_t* co_get_stackmem(stShareStack_t* share_stack)
{
	if (!share_stack)
	{
		return NULL;
	}
	int idx = share_stack->alloc_idx % share_stack->count;
	share_stack->alloc_idx++;

	return share_stack->stack_array[idx];
}


// ----------------------------------------------------------------------------
struct stTimeoutItemLink_t;
struct stTimeoutItem_t;

//epolling 控制块,内部封装了 Linux的 epolling 对象,以及时间轮定时器等
struct stCoEpoll_t
{
	//Linux 中epoll实例的文件描述符,直接使用 epolling_create()接口创建的
	int iEpollFd;
	//一次epoll_wait()最多返回的就绪事件个数,epoll_wait()系统调用的第三个参数
	static const int _EPOLL_SIZE = 1024 * 10;

	//时间轮定时器
	struct stTimeout_t *pTimeout;

	//存放已经超时的的事件的链表
	struct stTimeoutItemLink_t *pstTimeoutList;

	//存放epoll_wait()得到的就绪事件和定时器超时事件
	struct stTimeoutItemLink_t *pstActiveList;

	//对epoll_wait()的第二个参数的封装，即一次epoll_wait()的结果集
	co_epoll_res *result; 

};
typedef void (*OnPreparePfn_t)( stTimeoutItem_t *,struct epoll_event &ev, stTimeoutItemLink_t *active );
typedef void (*OnProcessPfn_t)( stTimeoutItem_t *);

//用于存放超时 or 就绪的事件的事件控制块,被串到双向链表中,
//作为双向链表的 item,同一个链表中的元素,超时时间是相同的
struct stTimeoutItem_t
{

	enum
	{
		eMaxTimeout = 40 * 1000 //40s
	};
	stTimeoutItem_t *pPrev;
	stTimeoutItem_t *pNext;
	stTimeoutItemLink_t *pLink;

	//盲猜是过期时间
	unsigned long long ullExpireTime;

	//盲猜是预处理和后处理的回调函数
	OnPreparePfn_t pfnPrepare;
	OnProcessPfn_t pfnProcess;

	void *pArg; // 就是存放 co 的指针,可以通过强转成 co控制块指针,然后直接使用 co.resume()等 api
	bool bTimeout;	//是否已经超时
};

//存放 超时事件 or 就绪事件的链表的头尾指针,即相当于是双向链表的 mark 节点
struct stTimeoutItemLink_t
{
	stTimeoutItem_t *head;
	stTimeoutItem_t *tail;

};

//时间轮定时器
struct stTimeout_t
{
	stTimeoutItemLink_t *pItems;	//数组,数组中的每个元素都是一个双向链表的 mark 节点
	int iItemSize;					//pItems数组的长度

	//当前最近超时时间的时间戳,单位是 ms,co 初始化时,ullStart被初始化成当前时刻的时间戳
	unsigned long long ullStart;
	long long llStartIdx;			//当前最近的马上就要超时的事件对应的 idx
};

//初始化一个每个 thread 共用一个的时间轮,这个时间轮的精度是 ms,最大可以存放 1min 的超时事件,所以有一个60 * 1000 大小的
//存放链表的数组,每个元素存放了一个双向链表的头尾指针,位于双向链表上的stTimeoutItem_t对象的过期时间相同.
stTimeout_t *AllocTimeout( int iSize )
{
	stTimeout_t *lp = (stTimeout_t*)calloc( 1,sizeof(stTimeout_t) );	

	lp->iItemSize = iSize;
	lp->pItems = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );

	//初始化成当前的 ms
	lp->ullStart = GetTickMS();
	//初始化成 idx = 0
	lp->llStartIdx = 0;

	return lp;
}

//释放时间轮
void FreeTimeout( stTimeout_t *apTimeout )
{
	free( apTimeout->pItems );
	free ( apTimeout );
}

//将一个定时事件加入到时间轮中,从数据结构的视角来看,是
//向时间轮中根据当前的时间和超时的事件添加一个双向链表中的item
int AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,unsigned long long allNow )
{
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}
	if( allNow < apTimeout->ullStart )
	{
		//传进来的当前的事件不能比当前的时间轮中的最近的一个事件的过期时间还要早,否则报错
		co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
					__LINE__,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	if( apItem->ullExpireTime < allNow )
	{
		//传进来的事件的过期时间也不能比传进来的当前的时间早,否则报错
		co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
					__LINE__,apItem->ullExpireTime,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	//计算应该放在时间轮的哪个位置.ullStart指向了当前的时间轮中的最早过期的一个事件的过期时间
	//这样减一手就能得到我们要插入的事件的距离最近的一个过期事件的偏移
	unsigned long long diff = apItem->ullExpireTime - apTimeout->ullStart;

	if( diff >= (unsigned long long)apTimeout->iItemSize )
	{
		//这个差值不能大于我们时间轮的大小
		diff = apTimeout->iItemSize - 1;
		co_log_err("CO_ERR: AddTimeout line %d diff %d",
					__LINE__,diff);

		//return __LINE__;
	}
	//串到时间轮的对应的双向链表的末尾
	//运算逻辑:
	//(时间轮数组头部 + 偏移量(注意是指针操作,对指针+1 = 实际地址+指针长度)
	AddTail( apTimeout->pItems + ( apTimeout->llStartIdx + diff ) % apTimeout->iItemSize , apItem );

	return 0;
}
inline void TakeAllTimeout( stTimeout_t *apTimeout,unsigned long long allNow,stTimeoutItemLink_t *apResult )
{
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}

	if( allNow < apTimeout->ullStart )
	{
		return ;
	}
	int cnt = allNow - apTimeout->ullStart + 1;
	if( cnt > apTimeout->iItemSize )
	{
		cnt = apTimeout->iItemSize;
	}
	if( cnt < 0 )
	{
		return;
	}
	for( int i = 0;i<cnt;i++)
	{
		int idx = ( apTimeout->llStartIdx + i) % apTimeout->iItemSize;
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( apResult,apTimeout->pItems + idx  );
	}
	apTimeout->ullStart = allNow;
	apTimeout->llStartIdx += cnt - 1;


}

//对传进 co 的实际执行的函数的封装,因为所有的 co  执行完其绑定的函数一定要 yield,否则程序出错,所以做了这一层
//封装,让业务层代码不用 yield
static int CoRoutineFunc( stCoRoutine_t *co,void * )
{
	if( co->pfn )
	{
		co->pfn( co->arg );
	}
	co->cEnd = 1;

	stCoRoutineEnv_t *env = co->env;

	//代码执行到这里,co绑定的函数的代码已经执行完了,必须要使用yield_env返回调用者
	co_yield_env( env );

	return 0;
}


//创建一个co控制块
struct stCoRoutine_t *co_create_env( stCoRoutineEnv_t * env, const stCoRoutineAttr_t* attr,
		pfn_co_routine_t pfn,void *arg )
{

	stCoRoutineAttr_t at;
	//更改传入的栈的大小为合法大小
	if( attr )
	{
		memcpy( &at,attr,sizeof(at) );
	}
	if( at.stack_size <= 0 )
	{
		at.stack_size = 128 * 1024;
	}
	else if( at.stack_size > 1024 * 1024 * 8 )
	{
		at.stack_size = 1024 * 1024 * 8;
	}

	if( at.stack_size & 0xFFF ) 
	{
		at.stack_size &= ~0xFFF;
		at.stack_size += 0x1000;
	}

	//初始化co控制块
	stCoRoutine_t *lp = (stCoRoutine_t*)malloc( sizeof(stCoRoutine_t) );
	
	memset( lp,0,(long)(sizeof(stCoRoutine_t))); 


	lp->env = env;
	lp->pfn = pfn;
	lp->arg = arg;

	stStackMem_t* stack_mem = NULL;
	if( at.share_stack )
	{
		//如果配置的是使用共享栈,那么从已经分配好的共享栈中划分一个区域,并且获取一个控制块
		stack_mem = co_get_stackmem( at.share_stack);
		at.stack_size = at.share_stack->stack_size;
	}
	else
	{
		//如果配置的是独立栈,那么直接分配一个子栈
		stack_mem = co_alloc_stackmem(at.stack_size);
	}
	//赋值栈的地址
	lp->stack_mem = stack_mem;

	//将栈的地址填充到co 的上下文中,这样下次 co 切换,co 可以直接使用这个栈当做自己程序的栈
	lp->ctx.ss_sp = stack_mem->stack_buffer;
	lp->ctx.ss_size = at.stack_size;

	//初始化剩下的stStackMem_t结构
	lp->cStart = 0;
	lp->cEnd = 0;
	lp->cIsMain = 0;
	lp->cEnableSysHook = 0;
	lp->cIsShareStack = at.share_stack != NULL;

	lp->save_size = 0;
	lp->save_buffer = NULL;

	return lp;
}

int co_create( stCoRoutine_t **ppco,const stCoRoutineAttr_t *attr,pfn_co_routine_t pfn,void *arg )
{
	if( !co_get_curr_thread_env() ) 
	{
		//如果当前的thread的env没有被初始化，那么初始化一下
		co_init_curr_thread_env();
	}
	//使用传进来的参数,初始化一手本 co 的env
	stCoRoutine_t *co = co_create_env( co_get_curr_thread_env(), attr, pfn,arg );
	*ppco = co;
	return 0;
}
void co_free( stCoRoutine_t *co )
{
    if (!co->cIsShareStack) 
    {    
        free(co->stack_mem->stack_buffer);
        free(co->stack_mem);
    }   
    //walkerdu fix at 2018-01-20
    //存在内存泄漏
    else 
    {
        if(co->save_buffer)
            free(co->save_buffer);

        if(co->stack_mem->occupy_co == co)
            co->stack_mem->occupy_co = NULL;
    }

    free( co );
}
void co_release( stCoRoutine_t *co )
{
    co_free( co );
}

void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co);

//运行参数co指向的co
void co_resume( stCoRoutine_t *co )
{
	//获取当前的线程env
	stCoRoutineEnv_t *env = co->env;
	//获取当前的co控制块
	stCoRoutine_t *lpCurrRoutine = env->pCallStack[ env->iCallStackSize - 1 ];
	if( !co->cStart )
	{
		//当且仅当首次启动携程时用到
		coctx_make( &co->ctx,(coctx_pfn_t)CoRoutineFunc,co,0 );
		co->cStart = 1;
	}
	//添加到调用链中,并且切换运行
	env->pCallStack[ env->iCallStackSize++ ] = co;
	co_swap( lpCurrRoutine, co );


}


// walkerdu 2018-01-14                                                                              
// 用于reset超时无法重复使用的协程                                                                  
void co_reset(stCoRoutine_t * co)
{
    if(!co->cStart || co->cIsMain)
        return;

    co->cStart = 0;
    co->cEnd = 0;

    // 如果当前协程有共享栈被切出的buff，要进行释放
    if(co->save_buffer)
    {
        free(co->save_buffer);
        co->save_buffer = NULL;
        co->save_size = 0;
    }

    // 如果共享栈被当前协程占用，要释放占用标志，否则被切换，会执行save_stack_buffer()
    if(co->stack_mem->occupy_co == co)
        co->stack_mem->occupy_co = NULL;
}

//进行co的切换，切换成return co
void co_yield_env( stCoRoutineEnv_t *env )
{
	//last 保存希望返回的 co
	stCoRoutine_t *last = env->pCallStack[ env->iCallStackSize - 2 ];
	//curr 保存当前的 co
	stCoRoutine_t *curr = env->pCallStack[ env->iCallStackSize - 1 ];

	env->iCallStackSize--;

	co_swap( curr, last);
}

//进行co的切换，切换成return co
void co_yield_ct()
{

	co_yield_env( co_get_curr_thread_env() );
}

//本质就是调用上面的co_yield_env
void co_yield( stCoRoutine_t *co )
{
	co_yield_env( co->env );
}

void save_stack_buffer(stCoRoutine_t* occupy_co)
{
	///copy out
	stStackMem_t* stack_mem = occupy_co->stack_mem;
	int len = stack_mem->stack_bp - occupy_co->stack_sp;

	if (occupy_co->save_buffer)
	{
		free(occupy_co->save_buffer), occupy_co->save_buffer = NULL;
	}

	occupy_co->save_buffer = (char*)malloc(len); //malloc buf;
	occupy_co->save_size = len;

	memcpy(occupy_co->save_buffer, occupy_co->stack_sp, len);
}

//切换运行的curr到pending_co运行
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co)
{
 	stCoRoutineEnv_t* env = co_get_curr_thread_env();

	//get curr stack sp
	//这里申请了一个 char 类型的变量,这个变量的地址即为当前的 stack top
	char c;
	curr->stack_sp= &c;

	if (!pending_co->cIsShareStack)
	{
		//如果不是共享栈的话,可以不用保存这两个指针
		env->pending_co = NULL;
		env->occupy_co = NULL;
	}
	else 
	{
		env->pending_co = pending_co;
		//get last occupy co on the same stack mem
		stCoRoutine_t* occupy_co = pending_co->stack_mem->occupy_co;
		//set pending co to occupy thest stack mem;
		pending_co->stack_mem->occupy_co = pending_co;

		env->occupy_co = occupy_co;
		if (occupy_co && occupy_co != pending_co)
		{
			save_stack_buffer(occupy_co);
		}
	}

	//swap context
	//这里执行汇编代码,将两个 co 的 ctx 切换
	coctx_swap(&(curr->ctx),&(pending_co->ctx) );

	//stack buffer may be overwrite, so get again;
	//这里已经切换到了pending co
	stCoRoutineEnv_t* curr_env = co_get_curr_thread_env();
	stCoRoutine_t* update_occupy_co =  curr_env->occupy_co;
	stCoRoutine_t* update_pending_co = curr_env->pending_co;
	
	if (update_occupy_co && update_pending_co && update_occupy_co != update_pending_co)
	{
		//resume stack buffer
		if (update_pending_co->save_buffer && update_pending_co->save_size > 0)
		{
			memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
		}
	}
}



//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t ;
struct stPoll_t : public stTimeoutItem_t 
{
	struct pollfd *fds;
	nfds_t nfds; // typedef unsigned long int nfds_t;

	stPollItem_t *pPollItems;

	int iAllEventDetach;

	int iEpollFd;

	int iRaiseCnt;


};
struct stPollItem_t : public stTimeoutItem_t
{
	struct pollfd *pSelf;
	stPoll_t *pPoll;

	struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.  
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
static uint32_t PollEvent2Epoll( short events )
{
	uint32_t e = 0;	
	if( events & POLLIN ) 	e |= EPOLLIN;
	if( events & POLLOUT )  e |= EPOLLOUT;
	if( events & POLLHUP ) 	e |= EPOLLHUP;
	if( events & POLLERR )	e |= EPOLLERR;
	if( events & POLLRDNORM ) e |= EPOLLRDNORM;
	if( events & POLLWRNORM ) e |= EPOLLWRNORM;
	return e;
}
static short EpollEvent2Poll( uint32_t events )
{
	short e = 0;	
	if( events & EPOLLIN ) 	e |= POLLIN;
	if( events & EPOLLOUT ) e |= POLLOUT;
	if( events & EPOLLHUP ) e |= POLLHUP;
	if( events & EPOLLERR ) e |= POLLERR;
	if( events & EPOLLRDNORM ) e |= POLLRDNORM;
	if( events & EPOLLWRNORM ) e |= POLLWRNORM;
	return e;
}

static __thread stCoRoutineEnv_t* gCoEnvPerThread = NULL;

//初始化当前的线程的env
void co_init_curr_thread_env()
{
	//分配线程控制块
	gCoEnvPerThread = (stCoRoutineEnv_t*)calloc( 1, sizeof(stCoRoutineEnv_t) );
	stCoRoutineEnv_t *env = gCoEnvPerThread;

	//初始化线程控制块参数
	env->iCallStackSize = 0;
	//初始化 mainco 的参数
	struct stCoRoutine_t *self = co_create_env( env, NULL, NULL,NULL );
	//在这里设置 mainco 的 cIsMain 是 1
	self->cIsMain = 1;

	env->pending_co = NULL;
	env->occupy_co = NULL;

	coctx_init( &self->ctx );

	//mainco 指针放在pCallStack[0]处
	env->pCallStack[ env->iCallStackSize++ ] = self;

	stCoEpoll_t *ev = AllocEpoll();
	SetEpoll( env,ev );
}
stCoRoutineEnv_t *co_get_curr_thread_env()
{
	return gCoEnvPerThread;
}

void OnPollProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

void OnPollPreparePfn( stTimeoutItem_t * ap,struct epoll_event &e,stTimeoutItemLink_t *active )
{
	stPollItem_t *lp = (stPollItem_t *)ap;
	lp->pSelf->revents = EpollEvent2Poll( e.events );


	stPoll_t *pPoll = lp->pPoll;
	pPoll->iRaiseCnt++;

	if( !pPoll->iAllEventDetach )
	{
		pPoll->iAllEventDetach = 1;

		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( pPoll );

		AddTail( active,pPoll );

	}
}


void co_eventloop( stCoEpoll_t *ctx,pfn_co_eventloop_t pfn,void *arg )
{
	if( !ctx->result )
	{
		//如果 ctx 的 result 没有被初始化,那么初始化一手
		ctx->result =  co_epoll_res_alloc( stCoEpoll_t::_EPOLL_SIZE );
	}
	co_epoll_res *result = ctx->result;


	for(;;)
	{
		//调用epolling_wait()等待IO就绪，设置timeout为1ms
		int ret = co_epoll_wait( ctx->iEpollFd,result,stCoEpoll_t::_EPOLL_SIZE, 1 );

		//代码执行到这里,可能是时间已经超时了,也可能是有 IO 请求过来了
		//总之ret 中保存了返回的事件,result里面放了epoll 系统调用的结果
		stTimeoutItemLink_t *active = (ctx->pstActiveList);		//当前执行环境的pstActiveList队列，可能已经有活跃的待处理事件
		stTimeoutItemLink_t *timeout = (ctx->pstTimeoutList);	//临时链表

		memset( timeout,0,sizeof(stTimeoutItemLink_t) );

		for(int i=0;i<ret;i++)
		{
			//处理就绪的文件描述符
			stTimeoutItem_t *item = (stTimeoutItem_t*)result->events[i].data.ptr;
			if( item->pfnPrepare )
			{
				//如果用户设置了预处理回调函数，那么执行这个函数
				item->pfnPrepare( item,result->events[i],active );
			}
			else
			{
				//如果用户没有注册回调函数，那么将其加入到active队列中
				AddTail( active,item );
			}
		}

		//从时间轮中取出所有的超时的事件，然后放入到timeout队列中
		unsigned long long now = GetTickMS();
		TakeAllTimeout( ctx->pTimeout,now,timeout );

		stTimeoutItem_t *lp = timeout->head;
		while( lp )
		{
			//遍历超时队列，将所有的事件的设置为true
			//printf("raise timeout %p\n",lp);
			lp->bTimeout = true;
			lp = lp->pNext;
		}

		//将active和timeout队列合并到 active 链表中
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( active,timeout );

		lp = active->head;
		while( lp )
		{
			//遍历一手 active 和 timeout 合起来的链表
			PopHead<stTimeoutItem_t,stTimeoutItemLink_t>( active );
            if (lp->bTimeout && now < lp->ullExpireTime) 
			{
				//如果过期了,但是ullExpireTime还没有到
				//大概是处理在 libco 中没有超时事件,但是在原生 epoll_wait()中超时的事件?
				int ret = AddTimeout(ctx->pTimeout, lp, now);
				if (!ret) 
				{
					lp->bTimeout = false;
					lp = active->head;
					continue;
				}
			}
			if( lp->pfnProcess )
			{
				lp->pfnProcess( lp );
			}

			lp = active->head;
		}
		if( pfn )
		{
			if( -1 == pfn( arg ) )
			{
				break;
			}
		}

	}
}
void OnCoroutineEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

//初始化 epolling 结构体
stCoEpoll_t *AllocEpoll()
{
	stCoEpoll_t *ctx = (stCoEpoll_t*)calloc( 1,sizeof(stCoEpoll_t) );

	ctx->iEpollFd = co_epoll_create( stCoEpoll_t::_EPOLL_SIZE );
	ctx->pTimeout = AllocTimeout( 60 * 1000 );
	
	ctx->pstActiveList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );
	ctx->pstTimeoutList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );


	return ctx;
}

void FreeEpoll( stCoEpoll_t *ctx )
{
	if( ctx )
	{
		free( ctx->pstActiveList );
		free( ctx->pstTimeoutList );
		FreeTimeout( ctx->pTimeout );
		co_epoll_res_free( ctx->result );
	}
	free( ctx );
}

//两个获取当前的 co 的 api
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env )
{
	return env->pCallStack[ env->iCallStackSize - 1 ];
}
stCoRoutine_t *GetCurrThreadCo( )
{
	stCoRoutineEnv_t *env = co_get_curr_thread_env();
	if( !env ) return 0;
	return GetCurrCo(env);
}



typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
int co_poll_inner( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc)
{
    if (timeout == 0)
	{
		return pollfunc(fds, nfds, timeout);
	}
	if (timeout < 0)
	{
		timeout = INT_MAX;
	}
	int epfd = ctx->iEpollFd;
	stCoRoutine_t* self = co_self();

	//1.struct change
	stPoll_t& arg = *((stPoll_t*)malloc(sizeof(stPoll_t)));
	memset( &arg,0,sizeof(arg) );

	arg.iEpollFd = epfd;
	arg.fds = (pollfd*)calloc(nfds, sizeof(pollfd));
	arg.nfds = nfds;

	stPollItem_t arr[2];
	if( nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack)
	{
		arg.pPollItems = arr;
	}	
	else
	{
		arg.pPollItems = (stPollItem_t*)malloc( nfds * sizeof( stPollItem_t ) );
	}
	memset( arg.pPollItems,0,nfds * sizeof(stPollItem_t) );

	arg.pfnProcess = OnPollProcessEvent;
	arg.pArg = GetCurrCo( co_get_curr_thread_env() );
	
	
	//2. add epoll
	for(nfds_t i=0;i<nfds;i++)
	{
		arg.pPollItems[i].pSelf = arg.fds + i;
		arg.pPollItems[i].pPoll = &arg;

		arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
		struct epoll_event &ev = arg.pPollItems[i].stEvent;

		if( fds[i].fd > -1 )
		{
			ev.data.ptr = arg.pPollItems + i;
			ev.events = PollEvent2Epoll( fds[i].events );

			int ret = co_epoll_ctl( epfd,EPOLL_CTL_ADD, fds[i].fd, &ev );
			if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL)
			{
				if( arg.pPollItems != arr )
				{
					free( arg.pPollItems );
					arg.pPollItems = NULL;
				}
				free(arg.fds);
				free(&arg);
				return pollfunc(fds, nfds, timeout);
			}
		}
		//if fail,the timeout would work
	}

	//3.add timeout
	//将事件加入到时间轮中
	unsigned long long now = GetTickMS();
	arg.ullExpireTime = now + timeout;
	int ret = AddTimeout( ctx->pTimeout,&arg,now );
	int iRaiseCnt = 0;
	if( ret != 0 )
	{
		co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
				ret,now,timeout,arg.ullExpireTime);
		errno = EINVAL;
		iRaiseCnt = -1;

	}
    else
	{
		co_yield_env( co_get_curr_thread_env() );
		iRaiseCnt = arg.iRaiseCnt;
	}

    {
		//clear epoll status and memory
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &arg );
		for(nfds_t i = 0;i < nfds;i++)
		{
			int fd = fds[i].fd;
			if( fd > -1 )
			{
				co_epoll_ctl( epfd,EPOLL_CTL_DEL,fd,&arg.pPollItems[i].stEvent );
			}
			fds[i].revents = arg.fds[i].revents;
		}


		if( arg.pPollItems != arr )
		{
			free( arg.pPollItems );
			arg.pPollItems = NULL;
		}

		free(arg.fds);
		free(&arg);
	}

	return iRaiseCnt;
}

int	co_poll( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout_ms )
{
	return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

void SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev )
{
	env->pEpoll = ev;
}
stCoEpoll_t *co_get_epoll_ct()
{
	if( !co_get_curr_thread_env() )
	{
		co_init_curr_thread_env();
	}
	return co_get_curr_thread_env()->pEpoll;
}
struct stHookPThreadSpec_t
{
	stCoRoutine_t *co;
	void *value;

	enum 
	{
		size = 1024
	};
};
void *co_getspecific(pthread_key_t key)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_getspecific( key );
	}
	return co->aSpec[ key ].value;
}
int co_setspecific(pthread_key_t key, const void *value)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_setspecific( key,value );
	}
	co->aSpec[ key ].value = (void*)value;
	return 0;
}



void co_disable_hook_sys()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( co )
	{
		co->cEnableSysHook = 0;
	}
}
bool co_is_enable_sys_hook()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	return ( co && co->cEnableSysHook );
}

stCoRoutine_t *co_self()
{
	return GetCurrThreadCo();
}

//co cond
//co的 cond 的双向链表的 mark 节点
struct stCoCond_t;

//一个cond 的双向链表的 item 节点
struct stCoCondItem_t 
{
	//用于串起双向链表,pPrev 指向链表中的上一个,pNext 指向链表中的下一个,
	//pLink 指向链表的 mark 节点
	stCoCondItem_t *pPrev;
	stCoCondItem_t *pNext;
	stCoCond_t *pLink;

	//是超时事件链表中的一个节点,即可以代表一个有超时时限的事件
	//实际上是位于本 co 对应的 thread 中的时间轮的双向链表的一个 item
	//如果本 cond 有超时时限的话,这个可以用来存放那个超时节点
	stTimeoutItem_t timeout;
};

//等待本 cond 的 CoCondItem的对象 
struct stCoCond_t
{
	stCoCondItem_t *head;
	stCoCondItem_t *tail;
};

//传入一个时间轮的 item,将该 item 中的 co 唤醒
static void OnSignalProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

stCoCondItem_t *co_cond_pop( stCoCond_t *link );
int co_cond_signal( stCoCond_t *si )
{
	stCoCondItem_t * sp = co_cond_pop( si );
	//从等待 cond 的双向链表中 pop 出等待本 cond的 第一个 co item
	if( !sp ) 
	{
		return 0;
	}

	//从时间轮双向链表中把 cond item 中保存的时间轮 item 给 remove 掉
	RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );

	//将其加入到 active 队列中,这样下次时间轮 tick 的时候就可以执行一手回调函数,唤醒阻塞 co
	AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );

	return 0;
}
int co_cond_broadcast( stCoCond_t *si )
{
	for(;;)
	{
		stCoCondItem_t * sp = co_cond_pop( si );
		if( !sp ) return 0;

		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );

		AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );
	}

	return 0;
}

//wait 一手 link 指向的 cond,最大等待时间为 ms
int co_cond_timedwait( stCoCond_t *link,int ms )
{
	//分配一个用于控制 cond 的 双向链表的 item 节点(下面简称 psi)
	stCoCondItem_t* psi = (stCoCondItem_t*)calloc(1, sizeof(stCoCondItem_t));
	//将当前的 co 的控制块传入时间轮双向链表的 item 中,这样下次就可以通过其中的指针控制本 co
	psi->timeout.pArg = GetCurrThreadCo();
	//设置超时的回调函数是唤醒本 co
	psi->timeout.pfnProcess = OnSignalProcessEvent;

	if( ms > 0 )
	{
		//如果设置了超时的时间,那么需要将本
		unsigned long long now = GetTickMS();
		psi->timeout.ullExpireTime = now + ms;

		//将psi 中的时间轮双线链表中的 item 注册到时间轮中,这样本 cond 就可以定时了
		int ret = AddTimeout( co_get_curr_thread_env()->pEpoll->pTimeout,&psi->timeout,now );
		if( ret != 0 )
		{
			free(psi);
			return ret;
		}
	}

	//同时把本 item 加到wait本 cond 的双向链表的末尾
	AddTail( link, psi);

	//执行 yield,切除本 co,返回上层 co
	co_yield_ct();

	//如果代码执行到这里,说明本 co 继续执行,可能是因为超时了,超时的话在时间轮的 tick 函数中回调上面设置好的
	//OnSignalProcessEvent函数,将自己唤醒,也可能是wait 的 cond 被 signal,总之这时候
	//应该把 psi 从本 cond 的双向链表中移除,并 free 掉
	RemoveFromLink<stCoCondItem_t,stCoCond_t>( psi );
	free(psi);

	return 0;
}
stCoCond_t *co_cond_alloc()
{
	return (stCoCond_t*)calloc( 1,sizeof(stCoCond_t) );
}
int co_cond_free( stCoCond_t * cc )
{
	free( cc );
	return 0;
}


stCoCondItem_t *co_cond_pop( stCoCond_t *link )
{
	stCoCondItem_t *p = link->head;
	if( p )
	{
		PopHead<stCoCondItem_t,stCoCond_t>( link );
	}
	return p;
}

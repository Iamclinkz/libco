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


#ifndef __CO_ROUTINE_INNER_H__

#include "co_routine.h"
#include "coctx.h"
struct stCoRoutineEnv_t;
struct stCoSpec_t
{
	void *value;
};

//子栈的控制块结构
struct stStackMem_t
{
	stCoRoutine_t* occupy_co;		//占有此共享栈的 co
	int stack_size;
	char* stack_bp; //stack_buffer + stack_size 即共享栈栈顶
	char* stack_buffer;		//共享栈栈底

};


//共享栈控制块指针,每个共享栈有count个子栈,子栈的控制块在stack_array数组中
struct stShareStack_t
{
	//作为stack_array的第一维的索引,指向下一个应该被分配的子栈的控制块的下标
	unsigned int alloc_idx;
	//总的共享栈的大小
	int stack_size;
	//本共享栈被划分成多少个小的栈(即stack_array的第一维对多到几)
	int count;
	//存放子栈控制块结构体指针的数组
	stStackMem_t** stack_array;
};


//协程控制块结构
struct stCoRoutine_t
{
	//指定了协程的环境，由于不支持协程在线程之间的迁移，所以属于是同一个线程的所有协程的执行环境，
	//即指向的是本co对应的thread的环境
	stCoRoutineEnv_t *env;
	//实际待执行的协程函数
	pfn_co_routine_t pfn;
	//待执行协程参数
	void *arg;
	//用于协程切换保留上下文,即保存esp、ebp、eip 和其他通用寄存器的值。
	coctx_t ctx;

	//本协程的各种标志
	char cStart;
	char cEnd;
	char cIsMain;			//是否是首个 co
	char cEnableSysHook;	//是否hook一手系统调用
	char cIsShareStack;		//是否使用共享栈

	//保存程序的环境变量的指针
	void *pvEnv;

	//char sRunStack[ 1024 * 128 ];
	//这里指向了本 co 运行的时候实际指向的栈内存的地址
	stStackMem_t* stack_mem;


	//save satck buffer while confilct on same stack_buffer;
	char* stack_sp; 
	unsigned int save_size;
	char* save_buffer;

	stCoSpec_t aSpec[1024];

};



//1.env
void 				co_init_curr_thread_env();
stCoRoutineEnv_t *	co_get_curr_thread_env();

//2.coroutine
void    co_free( stCoRoutine_t * co );
void    co_yield_env(  stCoRoutineEnv_t *env );

//3.func



//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t ;

stTimeout_t *AllocTimeout( int iSize );
void 	FreeTimeout( stTimeout_t *apTimeout );
int  	AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,uint64_t allNow );

struct stCoEpoll_t;
stCoEpoll_t * AllocEpoll();
void 		FreeEpoll( stCoEpoll_t *ctx );

stCoRoutine_t *		GetCurrThreadCo();
void 				SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev );

typedef void (*pfnCoRoutineFunc_t)();

#endif

#define __CO_ROUTINE_INNER_H__

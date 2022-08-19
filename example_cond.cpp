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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <queue>
#include "co_routine.h"
using namespace std;

//模拟的task的结构
struct stTask_t
{
	int id;
};

//模拟的任务的执行环境,即存在一个用于通知可以执行任务的 cond 变量和实际存放任务的 task_queue 变量
struct stEnv_t
{
	stCoCond_t* cond;					//等待本 cond 的 co 的链表
	queue<stTask_t*> task_queue;		//实际存放task的队列
};

void* Producer(void* args)
{
	co_enable_hook_sys();
	//把传进来的参数转换成stEnv_t类型
	stEnv_t* env=  (stEnv_t*)args;
	int id = 0;
	while (true)
	{
		//创建一个模拟的 task
		stTask_t* task = (stTask_t*)calloc(1, sizeof(stTask_t));
		task->id = id++;
		//把模拟的 task push 到任务队列中
		env->task_queue.push(task);
		printf("%s:%d produce task %d\n", __func__, __LINE__, task->id);
		co_cond_signal(env->cond);
		//这里的 poll 实际上被 libco hook 了,不是标准库的 poll 了
		poll(NULL, 0, 1000);
	}
	return NULL;
}
void* Consumer(void* args)
{
	co_enable_hook_sys();
	stEnv_t* env = (stEnv_t*)args;
	while (true)
	{
		//检查是否是empty,如果是的话,cond wait一手
		//注意这里实际上只有一个线程,所以消费者线程和生产者线程不存在竞争的关系,所以也就
		//不需要加锁的访问临界资源
		if (env->task_queue.empty())
		{
			//如果队列是空的的话,wait 一手
			co_cond_timedwait(env->cond, -1);
			continue;
		}
		//代码执行到这里,队列中肯定有东西了,所以取出,然后 pop 一手
		stTask_t* task = env->task_queue.front();
		env->task_queue.pop();
		printf("%s:%d consume task %d\n", __func__, __LINE__, task->id);
		free(task);
	}
	return NULL;
}
int main()
{
	//初始化生产者,消费者的共享的队列
	stEnv_t* env = new stEnv_t;
	env->cond = co_cond_alloc();

	//创建消费者co,放到consumer_routine中
	stCoRoutine_t* consumer_routine;
	co_create(&consumer_routine, NULL, Consumer, env);
	co_resume(consumer_routine);

	//创建生产者co
	stCoRoutine_t* producer_routine;
	co_create(&producer_routine, NULL, Producer, env);
	co_resume(producer_routine);
	
	co_eventloop(co_get_epoll_ct(), NULL, NULL);
	return 0;
}

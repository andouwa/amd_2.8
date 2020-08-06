/**********************************************************************
Copyright ©2012 Advanced Micro Devices, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

•	Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
•	Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************/
#ifndef  DEVICE_H
#define  DEVICE_H

#include <string.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <time.h>
#include <CL/opencl.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <linux/limits.h>
#endif

#define  SDK_SUCCESS 0
#define  SDK_FAILURE 1
#define  WIDTH 64*1024
#define  HEIGHT 512
#define  NUM_THREADS 64*1024*512
#define  NUM_GROUP_THREADS 1024*512
#define GROUP 64

//macro function for opencl API check.
#define  CHECK_CL_ERROR(status,msg)\
	if (CL_SUCCESS != status )\
{\
	std::cout<<"Error:"<<msg<<std::endl;\
	return SDK_FAILURE;\
}

/* Timer class to handle time measuring functionality */
class  Timer
{
public:
	int createTimer();
	int startTimer();
	int resetTimer();
	int stopTimer();
	double readTimer();
private:
	long long _freq; // clock frequency
	long long _clocks;// number of ticks at end
	long long _start;//start point ticks
	double totaltime;//time elapsed
};

class Device
{
public:

	//CL Objects and memory buffers
	int status;
	cl_device_type dType;            //device type
	cl_device_id deviceId;            //device ID
	cl_context context;                 //context
	cl_command_queue queue;     //command-queue
	cl_mem inputBuffer;               //input buffer
	cl_mem outputBuffer;            //output buffer
	cl_program program;             //program object
	cl_kernel kernel;           //kernel object
	cl_event eventObject;       //event object

	cl_ulong kernelStartTime;   //kernel start time
	cl_ulong kernelEndTime;     //kernel end time
	double elapsedTime;         //elapsed time in ms
	cl_int eventStatus;       //command queue event status flag
	size_t globalThreads[2] ;
	size_t localThreads[2] ;

	Device();
	~Device();

};
#endif /* #ifndef MULTI_GPU_H */

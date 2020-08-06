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
#include "device.h"
#include <math.h>

//Class Timer member function implementation
int Timer::createTimer()
{
	_start  = 0;
	_clocks = 0;

#ifdef  _WIN32
	QueryPerformanceFrequency((LARGE_INTEGER* )&_freq);
#else
	_freq = (long long)1.0E3;
#endif
	return SDK_SUCCESS;
}

//Start the Timer 
int Timer::startTimer()
{
#ifdef  _WIN32
	QueryPerformanceCounter((LARGE_INTEGER*)&_start);
#else
	struct timeval s;
	gettimeofday(&s,0);
	_start = (long long)s.tv_sec * (long long)1.0E3 + (long long)s.tv_usec / (long long)1.0E3;
#endif
	return SDK_SUCCESS;
}

//Reset the Timer
int Timer::resetTimer()
{
	_start = 0;
	_clocks = 0;
	return SDK_SUCCESS;
}

//Stop the Timer
int Timer::stopTimer()
{
	long long n = 0;
#ifdef  _WIN32
	QueryPerformanceCounter((LARGE_INTEGER*)&n);
#else
	struct timeval s;
	gettimeofday(&s,0);
	n = (long long)s.tv_sec * (long long)1.0E3 + (long long)s.tv_usec / (long long)1.0E3;
#endif
	n -= _start;
	_start = 0;
	_clocks += n;
	return SDK_SUCCESS;
}

//Get the elapsed time between the Timer start and end
double Timer::readTimer()
{
	totaltime = double(_clocks);
	totaltime = double(totaltime / _freq);
	return totaltime;
}


//class Device member function implement

//Construction
Device::Device()
{
	globalThreads[0] = WIDTH / 4/GROUP;
	globalThreads[1] = HEIGHT;

	localThreads[0] = 64;
	localThreads[1] = 4;
}

//Deconstruction
Device::~Device()
{
	//deconstuctor
}



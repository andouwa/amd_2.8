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
#include "AESEncrypt.h"
#include <vector>

/*** Global variables***/
cl_uchar sbox[256] = 
{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 //0
, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 //1
, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 //2
, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 //3
, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 //4
, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf //5
, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 //6
, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 //7
, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 //8
, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb //9
, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 //A
, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 //B
, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a //C
, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e //D
, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf //E
, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};//F
//0      1    2      3     4    5     6     7      8    9     A      B    C     D     E     F

cl_uchar Rcon[255] = 
{ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39
, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a
, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8
, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef
, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc
, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b
, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3
, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94
, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35
, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f
, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04
, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63
, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd
, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb      };

//Separator
std::string sep = "----------------------------------------------------------";
bool verify = false;

// Pointer to list of  CPU and GPU devices
AESEncrypt *AESEncrypt_cpu;
AESEncrypt *AESEncrypt_gpu;

// Number of CPU and GPU devices 
int numCPUDevices;
int numGPUDevices;

// Size of input data
int width;

//the time of simple CPU running time
double timeCPU;

//the time of simple GPU running time
double timeGPU;

// Input data for all devices
cl_uchar *input;     
cl_uchar *output;
// Host Output data for verification
cl_uchar *verificationOutput;

//to mark the subbuffer of multi GPU computed
cl_mem *subbufferInput;
cl_mem *subbufferOutput;

std::vector<int> gpuId;

// Kernel source string
std::string sourceStr;
const char *source;

// Context properties
const cl_context_properties* cprops;
cl_context_properties cps[3];

cl_platform_id platform = NULL;

// Count for verification
cl_uint verificationCount = 0;
cl_uint requiredCount = 0;

//AES key for each device task
cl_uchar   *global_key;   

//setup AES 
AESEncrypt::AESEncrypt()
{
	output = NULL;
}

int AESEncrypt::setupAESEncryp()
{

	keySizeBits = 128;
	rounds = 10;
	// 1 Byte = 8 bits 
	keySize = keySizeBits/8;
	// due to unknown represenation of cl_uchar 
	keySizeBits = keySize * sizeof(cl_uchar);
	key = (cl_uchar*)malloc(keySizeBits);
	if (!key)
	{
		std::cout << "Error: Failed to allocate key memory" <<std::endl;
	}

	// random initialization of key 
	for (unsigned int i=0; i< keySize; i++)
	{
		key[i] = global_key[i];
	}

	// expand the key 
	explandedKeySize = (rounds + 1) * keySize;

	expandedKey = (cl_uchar*)malloc(explandedKeySize * sizeof(cl_uchar));
	if (!expandedKey)
	{
		std::cout << "Failed to allocate memory(expandedKey)" <<std::endl;
	}

	roundKey    = (cl_uchar*)malloc(explandedKeySize * sizeof(cl_uchar));
	if (!roundKey)
	{
		std::cout << "Failed to allocate memory(roundKey)" <<std::endl;
	}

	keyExpansion(key, expandedKey, keySize, explandedKeySize);
	for(cl_uint i = 0; i < rounds + 1; ++i)
	{
		createRoundKey(expandedKey + keySize * i, roundKey + keySize * i);
	}

	return SDK_SUCCESS;
}

void AESEncrypt::mixColumns(cl_uchar * state)
{
	cl_uchar column[4];
	for(cl_uint i = 0; i < 4; ++i)
	{
		for(cl_uint j = 0; j < 4; ++j)
		{
			column[j] = state[j * 4 + i];
		}

		mixColumn(column);

		for(cl_uint j = 0; j < 4; ++j)
		{
			state[j * 4 + i] = column[j];
		}
	}
}

void  AESEncrypt::subBytes(cl_uchar * state)
{
	for(cl_uint i = 0; i < keySize; ++i)
	{
		state[i] = getSBoxValue(state[i]);
	}
}

void  AESEncrypt::shiftRow(cl_uchar *state, cl_uchar nbr)
{
	for(cl_uint i = 0; i < nbr; ++i)
	{
		cl_uchar tmp = state[0];
		for(cl_uint j = 0; j < 3; ++j)
		{
			state[j] = state[j + 1];
		}
		state[3] = tmp;
	}
}

cl_uchar AESEncrypt::getSBoxValue(cl_uint num)
{
	return sbox[num];
}

void AESEncrypt::addRoundKey(cl_uchar * state, cl_uchar * rKey)
{
	for(cl_uint i = 0; i < keySize; ++i)
	{
		state[i] = state[i] ^ rKey[i];
	}
}

void AESEncrypt::shiftRows(cl_uchar * state)
{
	for(cl_uint i = 0; i < 4; ++i)
	{
		shiftRow(state + i * 4, i);
	}
}

void AESEncrypt::createRoundKey(cl_uchar * eKey, cl_uchar * rKey)
{
	for(cl_uint i = 0; i < 4; ++i)
		for(cl_uint j = 0; j < 4; ++j)
		{
			rKey[i + j * 4] = eKey[i * 4 + j];
		}
}

cl_uchar AESEncrypt::getRconValue(cl_uint num)
{
	return Rcon[num];
}

cl_uchar AESEncrypt::galoisMultiplication(cl_uchar a, cl_uchar b)
{
	cl_uchar p = 0; 
	for(cl_uint i = 0; i < 8; ++i)
	{
		if((b & 1) == 1)
		{
			p ^= a;
		}
		cl_uchar hiBitSet = (a & 0x80);
		a <<= 1;
		if(hiBitSet == 0x80)
		{
			a ^= 0x1b;
		}
		b >>= 1;
	}
	return p;
}

void AESEncrypt::aesRound(cl_uchar * state, cl_uchar * rKey)
{
	subBytes(state);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, rKey);
}

void AESEncrypt::mixColumn(cl_uchar *column)
{
	cl_uchar cpy[4];
	for(cl_uint i = 0; i < 4; ++i)
	{
		cpy[i] = column[i];
	}
	column[0] = galoisMultiplication(cpy[0], 2)^
		galoisMultiplication(cpy[3], 1)^
		galoisMultiplication(cpy[2], 1)^
		galoisMultiplication(cpy[1], 3);

	column[1] = galoisMultiplication(cpy[1], 2)^
		galoisMultiplication(cpy[0], 1)^
		galoisMultiplication(cpy[3], 1)^
		galoisMultiplication(cpy[2], 3);

	column[2] = galoisMultiplication(cpy[2], 2)^
		galoisMultiplication(cpy[1], 1)^
		galoisMultiplication(cpy[0], 1)^
		galoisMultiplication(cpy[3], 3);

	column[3] = galoisMultiplication(cpy[3], 2)^
		galoisMultiplication(cpy[2], 1)^
		galoisMultiplication(cpy[1], 1)^
		galoisMultiplication(cpy[0], 3);
}

void AESEncrypt::aesMain(cl_uchar * state, cl_uchar * rKey, cl_uint rounds)
{
	addRoundKey(state, rKey);

	for(cl_uint i = 1; i < rounds; ++i)
	{
		aesRound(state, rKey + keySize*i);
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, rKey + keySize*rounds);
}

void AESEncrypt::keyExpansion(cl_uchar * key, cl_uchar * expandedKey,
	cl_uint keySize, cl_uint explandedKeySize)
{
	cl_uint currentSize = 0;
	cl_uint rConIteration = 1;
	cl_uchar temp[4] = {0};

	for(cl_uint i = 0; i < keySize; ++i)
	{
		expandedKey[i] = key[i];
	}

	currentSize += keySize;

	while(currentSize < explandedKeySize)
	{
		for(cl_uint i = 0; i < 4; ++i)
		{
			temp[i] = expandedKey[(currentSize - 4) + i];
		}

		if(currentSize%keySize == 0)
		{
			core(temp, rConIteration++);
		}

		//XXX: add extra SBOX here if the keySize is 32 Bytes
		for(cl_uint i = 0; i < 4; ++i)
		{
			expandedKey[currentSize] = expandedKey[currentSize - keySize] ^ temp[i];
			currentSize++;
		}
	}
}

void AESEncrypt::rotate(cl_uchar * word)
{
	cl_uchar c = word[0];
	for(cl_uint i = 0; i < 3; ++i)
	{
		word[i] = word[i + 1];
	}
	word[3] = c;
}

void AESEncrypt::core(cl_uchar * word, cl_uint iter)
{
	rotate(word);
	for(cl_uint i = 0; i < 4; ++i)
	{
		word[i] = getSBoxValue(word[i]);
	}
	word[0] = word[0] ^ getRconValue(iter);
}

int AESEncrypt::createContext()
{
	context = clCreateContext(cprops, 
		1, 
		&deviceId, 
		0, 
		0, 
		&status);
	CHECK_CL_ERROR(status, "clCreateContext failed.");

	return SDK_SUCCESS;
}

//Create Command-Queue
int AESEncrypt::createQueue()
{
	queue = clCreateCommandQueue(context, 
		deviceId, 
		CL_QUEUE_PROFILING_ENABLE, 
		&status);
	CHECK_CL_ERROR(status, "clCreateCommandQueue failed.");

	return SDK_SUCCESS;
}

// Create input buffer and output buffer
int AESEncrypt::createBuffers()
{
	inputBuffer = clCreateBuffer(context, 
		CL_MEM_READ_ONLY, 
		width * sizeof(cl_uchar), 
		0, 
		&status);
	CHECK_CL_ERROR(status, "clCreateBuffer failed.(inputBuffer)");

	outputBuffer = clCreateBuffer(context, 
		CL_MEM_WRITE_ONLY, 
		width * sizeof(cl_uchar), 
		0, 
		&status);
	CHECK_CL_ERROR(status, "clCreateBuffer failed.(outputBuffer)");

	rKeyBuffer = clCreateBuffer(
		context, 
		CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
		sizeof(cl_uchar ) * explandedKeySize,
		roundKey,
		&status);
	CHECK_CL_ERROR(status, "clCreateBuffer failed. (rKeyBuffer)");

	cl_uchar * sBox;
	sBox = (cl_uchar *)sbox;
	sBoxBuffer = clCreateBuffer(
		context, 
		CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
		sizeof(cl_uchar ) * 256,
		sBox,
		&status);
	CHECK_CL_ERROR(status, "clCreateBuffer failed. (sBoxBuffer)");

	return SDK_SUCCESS;
}

// Initialize input buffer
int AESEncrypt::enqueueWriteBuffer()
{
		status = clEnqueueWriteBuffer(queue,
		inputBuffer,
		CL_TRUE, 
		0, 
		width * sizeof(cl_uchar),
		input,
		0, 0, 0);
	CHECK_CL_ERROR(status, "clEnqueueWriteBuffer failed.");

	return SDK_SUCCESS;
}

// Create program with source
int AESEncrypt::createProgram(const char **source, const size_t *sourceSize)
{	
	program = clCreateProgramWithSource(context, 
		1, 
		source, 
		sourceSize, 
		&status);
	CHECK_CL_ERROR(status, "clCreateProgramWithSource failed.");

	return SDK_SUCCESS;
}

// Build program source
int AESEncrypt::buildProgram()
{
	status = clBuildProgram(program, 
		1, 
		&deviceId, 
		NULL, 0, 0);

	// Print build log here if build program failed
	if(status != CL_SUCCESS)
	{
		if(status == CL_BUILD_PROGRAM_FAILURE)
		{
			cl_int logStatus;
			char *buildLog = NULL;
			size_t buildLogSize = 0;
			logStatus = clGetProgramBuildInfo(program, 
				deviceId, 
				CL_PROGRAM_BUILD_LOG, 
				buildLogSize, 
				buildLog, 
				&buildLogSize);
			CHECK_CL_ERROR(status, "clGetProgramBuildInfo failed.");

			buildLog = (char*)malloc(buildLogSize);
			if(buildLog == NULL)
			{
				std::cout<<"Failed to allocate host memory. (buildLog)"<<std::endl;
				return SDK_FAILURE;
			}
			memset(buildLog, 0, buildLogSize);

			logStatus = clGetProgramBuildInfo(program, 
				deviceId, 
				CL_PROGRAM_BUILD_LOG, 
				buildLogSize, 
				buildLog, 
				NULL);
			if(logStatus != CL_SUCCESS)
			{
				std::cout << "clGetProgramBuildInfo failed.";
				free(buildLog);

				return SDK_FAILURE;
			}
			std::cout << " \n\t\t\tBUILD LOG\n";
			std::cout <<sep<<"\n"<<buildLog<<"\n"<< sep<<std::endl;
			free(buildLog);
		}
		CHECK_CL_ERROR(status, "clBuildProgram failed.");
	}

	return SDK_SUCCESS;
}

//Create kernel object
int AESEncrypt::createKernel()
{
	kernel = clCreateKernel(program, "AESEncrypt", &status);
	CHECK_CL_ERROR(status, "clCreateKernel failed.");

	return SDK_SUCCESS;
}

//set arguments for kernel
int AESEncrypt::setKernelArgs()
{
	status = clSetKernelArg(kernel, 0, sizeof(cl_mem), &outputBuffer);
	CHECK_CL_ERROR(status, "clSetKernelArg failed.(outputBuffer)");

	status = clSetKernelArg(kernel, 1, sizeof(cl_mem), &inputBuffer);
	CHECK_CL_ERROR(status, "clSetKernelArg failed.(inputBuffer)");

	status = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&rKeyBuffer);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (rKeyBuffer)");

	status = clSetKernelArg(kernel, 3, sizeof(cl_mem), (void *)&sBoxBuffer);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (SBoxBuffer)");

	status = clSetKernelArg(kernel, 4, localThreads[0] * localThreads[1] * 4 * sizeof (cl_uchar), NULL);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (block0)");

	status = clSetKernelArg(kernel, 5, localThreads[0] * localThreads[1] * 4 * sizeof(cl_uchar), NULL);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (block1)");

	status = clSetKernelArg(kernel, 6, sizeof(cl_uint), (void *)&width);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (width)");

	status = clSetKernelArg(kernel, 7, sizeof(cl_uint), (void *)&rounds);
	CHECK_CL_ERROR(status, "clSetKernelArg failed. (rounds)");

	return SDK_SUCCESS;
}

//Enqueue NDRange kernel
int AESEncrypt::enqueueKernel()
{
	status = clEnqueueNDRangeKernel(queue,
		kernel,
		2,
		NULL,
		globalThreads,
		localThreads,
		0,
		NULL,
		&eventObject);
	CHECK_CL_ERROR(status, "clEnqueueNDRangeKernel failed.");

	status = clFlush(queue);
	CHECK_CL_ERROR(status, "clFlush failed.");

	eventStatus = CL_QUEUED;

	return SDK_SUCCESS;
}

//Wait for kernel execution to finish
int AESEncrypt::waitForKernel()
{
	status = clFinish(queue);
	CHECK_CL_ERROR(status, "clFinish failed.");

	return SDK_SUCCESS;
}

//Get kernel execution time
int AESEncrypt::getKernelTime()
{
	status = clGetEventProfilingInfo(eventObject,
		CL_PROFILING_COMMAND_START,
		sizeof(cl_ulong),
		&kernelStartTime,
		0);
	CHECK_CL_ERROR(status, "clGetEventProfilingInfo failed.(start time)");

	status = clGetEventProfilingInfo(eventObject,
		CL_PROFILING_COMMAND_END,
		sizeof(cl_ulong),
		&kernelEndTime,
		0);
	CHECK_CL_ERROR(status, "clGetEventProfilingInfo failed.(end time)");

	//Measure time in ms
	elapsedTime = 1e-6 * (kernelEndTime - kernelStartTime);

	return SDK_SUCCESS;
}

//migrate the buffers between devices
int AESEncrypt::enqueueMigrateMemObjects()
{
	cl_mem buffers[] = {inputBuffer};

	status = clEnqueueMigrateMemObjects(queue,
		1,
		buffers,
		CL_MIGRATE_MEM_OBJECT_CONTENT_UNDEFINED,
		0,0,0);
	CHECK_CL_ERROR(status, "clEnqueueMigrateMemObjects Failed.");

	status = clFinish(queue);
	CHECK_CL_ERROR(status, "clFinish Failed.");

	return SDK_SUCCESS;
}

//Get output data from device to host
int AESEncrypt::enqueueReadData()
{
	// Allocate memory 
	if(output == NULL)
	{
		output = (cl_uchar *)malloc((width) * sizeof(cl_uchar));
		if(!output)
		{
			std::cout << "Error: Failed to allocate out memory on host." <<std::endl;
		}
	}

	status = clEnqueueReadBuffer(queue,
		outputBuffer,
		CL_TRUE,
		0,
		(width) * sizeof(cl_uchar),
		output, 
		0, 0, 0);
	CHECK_CL_ERROR(status, "clEnqueueReadBuffer failed.");

	return SDK_SUCCESS;
}

// Verify results against host computation
int AESEncrypt::verifyResults()
{
	float error = 0;

	for(int i = 0; i < width; i++)
	{
		if (output[i] != verificationOutput[i])
		{
			error++;
		}
	}

	if(error < 0.001)
	{
		std::cout << "Passed!\n" << std::endl;
		verificationCount++;
	}
	else
	{
		std::cout << "Failed!\n" << std::endl;
		return SDK_FAILURE;
	}

	return SDK_SUCCESS;
}

//Get the status of the command queue
int AESEncrypt::getEventInfo()
{
	int status;

	status = clGetEventInfo(eventObject,
		CL_EVENT_COMMAND_EXECUTION_STATUS,
		sizeof(cl_int),
		&eventStatus,
		NULL);
	CHECK_CL_ERROR(status, "clGetEventInfo Failed");

	return CL_SUCCESS;
}

//Cleanup allocated resources
int AESEncrypt::cleanupResources()
{
	return SDK_SUCCESS;
}
// Converts the contents of a file into a string
std::string convertToString(const char *filename)
{
	size_t size;
	char*  str;
	std::string s;

	std::fstream f(filename, (std::fstream::in | std::fstream::binary));

	if(f.is_open())
	{
		size_t fileSize;
		f.seekg(0, std::fstream::end);
		size = fileSize = (size_t)f.tellg();
		f.seekg(0, std::fstream::beg);

		str = new char[size+1];
		if(!str)
		{
			f.close();
			return NULL;
		}

		f.read(str, fileSize);
		f.close();
		str[size] = '\0';

		s = str;
		delete[] str;
		return s;
	}
	return NULL;
}

// OpenCL related initialization 
//  Create Context, Device list, Command Queue
//Create OpenCL memory buffer objects
// Load CL file, compile, link CL source 
// Build program and kernel objects

int initializeCL()
{
	cl_int status = 0;

	cl_uint numPlatforms;
	status = clGetPlatformIDs(0, NULL, &numPlatforms);
	CHECK_CL_ERROR(status, "clGetPlatformIDs failed.");

	if(numPlatforms > 0)
	{
		cl_platform_id* platforms = (cl_platform_id *)malloc(numPlatforms*sizeof(cl_platform_id));
		status = clGetPlatformIDs(numPlatforms, platforms, NULL);
		CHECK_CL_ERROR(status, "clGetPlatformIDs failed.");

		platform = platforms[0];
		free(platforms);
	}
	cps[0] = CL_CONTEXT_PLATFORM;
	cps[1] = (cl_context_properties)platform;
	cps[2] = 0;
	cprops = (NULL == platform) ? NULL : cps;

	// Get Number of CPU devices available
	status = clGetDeviceIDs(platform,
		CL_DEVICE_TYPE_CPU, 
		0, 
		0, 
		(cl_uint*)&numCPUDevices);
	CHECK_CL_ERROR(status, "clGetDeviceIDs failed.(numCPUDevices)");

	// Get Number of GPU devices available
	status = clGetDeviceIDs(platform,
		CL_DEVICE_TYPE_GPU, 
		0, 
		0, 
		(cl_uint*)&numGPUDevices);
	CHECK_CL_ERROR(status, "clGetDeviceIDs failed.(numGPUDevices)");

	// If no GPU is present then exit
	if(numGPUDevices < 1)
	{
		std::cout<<"Only CPU device is present. Exiting!"<<std::endl;
		return SDK_FAILURE;
	}

	// Allocate memory for list of Devices
	AESEncrypt_cpu = new AESEncrypt[1];

	//Get CPU Device IDs
	cl_device_id* cpuDeviceIDs = new cl_device_id[1];
	status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 1, cpuDeviceIDs, 0);
	CHECK_CL_ERROR(status, "clGetDeviceIDs failed.");

	AESEncrypt_cpu[0].dType = CL_DEVICE_TYPE_CPU;
	AESEncrypt_cpu[0].deviceId = cpuDeviceIDs[0];

	delete[] cpuDeviceIDs;

	AESEncrypt_gpu = new AESEncrypt[numGPUDevices];
	//Get GPU Device IDs
	cl_device_id* gpuDeviceIDs = new cl_device_id[numGPUDevices];
	status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, numGPUDevices, gpuDeviceIDs, 0);
	CHECK_CL_ERROR(status, "clGetDeviceIDs failed.");

	for(int i = 0; i < numGPUDevices; i++)
	{
		AESEncrypt_gpu[i].dType = CL_DEVICE_TYPE_GPU;
		AESEncrypt_gpu[i].deviceId = gpuDeviceIDs[i];
	}

	delete[] gpuDeviceIDs;

	// Load CL file
	const char *filename  = "AdvancedMultiGPU_Kernels.cl";
	sourceStr = convertToString(filename);
	source = sourceStr.c_str();

	return SDK_SUCCESS;
}

// Host Initialization 
// Allocate and initialize memory on the host.
int initializeHost()
{
	width = NUM_THREADS;
	verificationOutput = NULL;

	verificationOutput =  (cl_uchar *) malloc(sizeof(cl_uchar) * width);
	if (!verificationOutput)
	{
		std::cout << "Error: Failed to allocate verificationOutput memory on host." <<std::endl;
	}

	input =  (cl_uchar*) malloc(sizeof(cl_uchar) *width);
	memset(input, 1,width);
	if (!input)
	{
		std::cout << "Error: Failed to allocate input memory on host." <<std::endl;
	}

	//AES
	global_key = (cl_uchar*)malloc(16*sizeof(cl_uchar));
	if (!global_key)
	{
		std::cout << "Error: Failed to allocate global_key memory" <<std::endl;
	}

	// random initialization of key 
	int seed = (unsigned int)time(NULL);
	srand(seed);

	for (int i=0; i< 16; i++)
	{
		global_key[i] = rand()%256;
	}

	return SDK_SUCCESS;
}

//case 1: use single CPU to compute
int runCPU()
{
	int status;
	cl_buffer_region bufferRegion;

	subbufferInput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);
	subbufferOutput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);

	//Set the argument about AES encrypt
	status = AESEncrypt_cpu[0].setupAESEncryp();
	CHECK_CL_ERROR(status, "setupAESEncryp(CPU) failed.");

	//create context for single CPU
	status = AESEncrypt_cpu[0].createContext();
	CHECK_CL_ERROR(status, "CreateContext(CPU) failed.");

	//create program for CPU
	size_t sourceSize = strlen(source);
	status = AESEncrypt_cpu[0].createProgram(&source, &sourceSize);
	CHECK_CL_ERROR(status, "CreateProgram(CPU) failed.");

	//build program for CPU
	status = AESEncrypt_cpu[0].buildProgram();
	CHECK_CL_ERROR(status, "BuildProgram(CPU) failed.");

	//create queue for CPU
	status = AESEncrypt_cpu[0].createQueue();
	CHECK_CL_ERROR(status ,"Creating Command Queue(CPU) failed");

	//create kernel for CPU
	status = AESEncrypt_cpu[0].createKernel();
	CHECK_CL_ERROR(status ,  "Creating Kernel (CPU) failed");

	// Create buffers for CPU
	status = AESEncrypt_cpu[0].createBuffers();
	CHECK_CL_ERROR(status, "createBuffers(CPU) failed.");

	//initialize the buffer data
	status = AESEncrypt_cpu[0].enqueueWriteBuffer();
	CHECK_CL_ERROR(status ,"Submitting Write OpenCL Buffer (CPU) failed");

	//Set kernel arguments
	status = AESEncrypt_cpu[0].setKernelArgs();
	CHECK_CL_ERROR(status , "Setting Kernel Args(CPU) failed");

	//Start a host timer here
	Timer cputime;
	cputime.createTimer();
	cputime.startTimer();

	for(int i =0; i < GROUP; i++)
	{
		bufferRegion.origin = i * NUM_GROUP_THREADS;
		bufferRegion.size = NUM_GROUP_THREADS;

		subbufferInput[i] = clCreateSubBuffer(AESEncrypt_cpu[0].inputBuffer,
			CL_MEM_READ_ONLY, 
			CL_BUFFER_CREATE_TYPE_REGION, 
			(void *)&bufferRegion, &status);
		CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

		subbufferOutput[i] = clCreateSubBuffer(AESEncrypt_cpu[0].outputBuffer,
			CL_MEM_WRITE_ONLY, 
			CL_BUFFER_CREATE_TYPE_REGION, 
			(void *)&bufferRegion, &status);
		CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

		//Set kernel arguments
		status = clSetKernelArg(AESEncrypt_cpu[0].kernel, 0, sizeof(cl_mem), &subbufferOutput[i]);
		CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

		status = clSetKernelArg(AESEncrypt_cpu[0].kernel, 1, sizeof(cl_mem), &subbufferInput[i]);
		CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

		//run the kernel.
		status = AESEncrypt_cpu[0].enqueueKernel();
		CHECK_CL_ERROR(status, "enqueueKernel(multi GPU) failed.");

		status = clFinish(AESEncrypt_cpu[0].queue);
		CHECK_CL_ERROR(status, "clFinish failed.");

	}

	//Wait for all kernels to finish execution
	status = AESEncrypt_cpu[0].waitForKernel();
	CHECK_CL_ERROR(status , "Waiting for Kernel(CPU) failed");

	//Stop the host timer here
	cputime.stopTimer();

	//Measure total time
	timeCPU = cputime.readTimer();

	//Print total time and individual times
	std::cout << "Total time : " << timeCPU * 1000 <<  " ms" << std::endl;

	if(verify)
	{
		//In order to save time. Use single CPU compute result sa verify samples
		status = AESEncrypt_cpu[0].enqueueReadData();
		CHECK_CL_ERROR(status ,"Submitting Read buffer (CPU) failed");

		// Verify results
		for(int i = 0; i < width; i++)
		{
			verificationOutput[i] = AESEncrypt_cpu[0].output[i];
		}
	}

	//Release the resources on all devices
	//Release context
	status = clReleaseContext(AESEncrypt_cpu[0].context);
	CHECK_CL_ERROR(status, "clCreateContext(CPU) failed.");

	//Release memory buffers
	status = clReleaseMemObject(AESEncrypt_cpu[0].inputBuffer);
	CHECK_CL_ERROR(status, "clReleaseMemObject failed(CPU). (inputBuffer)");

	status = clReleaseMemObject(AESEncrypt_cpu[0].outputBuffer);
	CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

	status = clReleaseMemObject(AESEncrypt_cpu[0].rKeyBuffer);
	CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

	status = clReleaseMemObject(AESEncrypt_cpu[0].sBoxBuffer);
	CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

	//Release Program object
	status = clReleaseProgram(AESEncrypt_cpu[0].program);
	CHECK_CL_ERROR(status, "clReleaseProgram failed(CPU).");

	//Release Kernel object, command-queue, event object
	status = clReleaseKernel(AESEncrypt_cpu[0].kernel);
	CHECK_CL_ERROR(status, "clReleaseCommandQueue failed(CPU).");

	status = clReleaseCommandQueue(AESEncrypt_cpu[0].queue);
	CHECK_CL_ERROR(status, "clReleaseCommandQueue failed(CPU).");

	status = clReleaseEvent(AESEncrypt_cpu[0].eventObject);
	CHECK_CL_ERROR(status, "clReleaseEvent failed(CPU).");

	return SDK_SUCCESS;
}

//case 2: use single GPU to compute
int runSingleGPU()
{
	int status;
	Timer *gputime;
	cl_buffer_region bufferRegion;

	subbufferInput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);
	subbufferOutput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);

	//create the context for all GPUs
	cl_context context = clCreateContextFromType(cprops,
		CL_DEVICE_TYPE_GPU,
		0,
		0,
		&status);
	CHECK_CL_ERROR(status, "clCreateContext(single GPU) failed.");

	//create the program for all GPUs
	size_t sourceSize = strlen(source);
	cl_program program  = clCreateProgramWithSource(context, 
		1, 
		&source, 
		(const size_t*)&sourceSize, 
		&status);
	CHECK_CL_ERROR(status, "clCreateProgramWithSource(single GPU) failed.");

	//Build program for all GPUs in the context
	status = clBuildProgram(program, 0, 0, NULL, 0, 0);
	CHECK_CL_ERROR(status, "clBuildProgram(single GPU) failed.");

	// Create buffers
	// Create input buffer for all GPUs
	cl_mem inputBuffer = clCreateBuffer(context, 
		CL_MEM_READ_ONLY, 
		width * sizeof(cl_float), 
		0, 
		&status);
	CHECK_CL_ERROR(status, "clCreateBuffer(single GPU) failed.(inputBuffer)");

	////Create output buffer for each GPU
	for (int i = 0; i < numGPUDevices ; i++)
	{
		status = AESEncrypt_gpu[i].setupAESEncryp();
		CHECK_CL_ERROR(status, "setupAESEncryp(CPU) failed.");

		AESEncrypt_gpu[i].outputBuffer = clCreateBuffer(context, 
			CL_MEM_WRITE_ONLY, 
			width * sizeof(cl_uchar), 
			0, 
			&status);
		CHECK_CL_ERROR(status, "clCreateBuffer failed.(outputBuffer)");

		AESEncrypt_gpu[i].rKeyBuffer = clCreateBuffer(
			context, 
			CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
			sizeof(cl_uchar ) * AESEncrypt_gpu[i].explandedKeySize,
			AESEncrypt_gpu[i].roundKey,
			&status);
		CHECK_CL_ERROR(status, "clCreateBuffer failed. (rKeyBuffer)");

		cl_uchar * sBox;
		sBox = (cl_uchar *)sbox;
		AESEncrypt_gpu[i].sBoxBuffer = clCreateBuffer(
			context, 
			CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
			sizeof(cl_uchar ) * 256,
			sBox,
			&status);
		CHECK_CL_ERROR(status, "clCreateBuffer failed. (sBoxBuffer)");

		//set the device class
		AESEncrypt_gpu[i].context = context;
		AESEncrypt_gpu[i].program = program;
		AESEncrypt_gpu[i].inputBuffer = inputBuffer;

		//create queue for each GPU
		status = AESEncrypt_gpu[i].createQueue();
		CHECK_CL_ERROR(status ,"Creating Commmand Queue(single GPU) failed");

		//create kernel for each GPU
		status = AESEncrypt_gpu[i].createKernel();
		CHECK_CL_ERROR(status , "Creating Kernel (single GPU) failed");

		//Set kernel arguments for each kernel
		status = AESEncrypt_gpu[i].setKernelArgs();
		CHECK_CL_ERROR(status , "Setting Kernel Args(single GPU) failed");
	}

	//initialize the buffer data
	status = AESEncrypt_gpu[0].enqueueWriteBuffer();
	CHECK_CL_ERROR(status ,"Submitting Write OpenCL Buffer (single GPU) failed");

	gputime = (Timer*)malloc(numGPUDevices * sizeof(Timer));

	for (int i = 0; i < numGPUDevices ; i++)
	{
		//Start a host timer here		
		gputime[i].createTimer();
		gputime[i].startTimer();

		for(int offset =0; offset < GROUP; offset++)
		{
			bufferRegion.origin = offset * NUM_GROUP_THREADS;
			bufferRegion.size = NUM_GROUP_THREADS;

			subbufferInput[offset] = clCreateSubBuffer(AESEncrypt_gpu[i].inputBuffer,
				CL_MEM_READ_ONLY, 
				CL_BUFFER_CREATE_TYPE_REGION, 
				(void *)&bufferRegion, &status);
			CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

			subbufferOutput[offset] = clCreateSubBuffer(AESEncrypt_gpu[i].outputBuffer,
				CL_MEM_WRITE_ONLY, 
				CL_BUFFER_CREATE_TYPE_REGION, 
				(void *)&bufferRegion, &status);
			CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

			//Set kernel arguments
			status = clSetKernelArg(AESEncrypt_gpu[i].kernel, 0, sizeof(cl_mem), &subbufferOutput[offset]);
			CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

			status = clSetKernelArg(AESEncrypt_gpu[i].kernel, 1, sizeof(cl_mem), &subbufferInput[offset]);
			CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

			//run the kernel.
			status = AESEncrypt_gpu[i].enqueueKernel();
			CHECK_CL_ERROR(status, "enqueueKernel(multi GPU) failed.");

			status = clFlush(AESEncrypt_gpu[i].queue);
			CHECK_CL_ERROR(status, "clFlush failed.");
		}

			status = clFinish(AESEncrypt_gpu[i].queue);
			CHECK_CL_ERROR(status, "clFinish failed.");

		//Stop the host timer here
		gputime[i].stopTimer();

		//Measure total time
		timeGPU = gputime[i].readTimer();

		//Print total time and individual times
		std::cout << "Time of GPU " << i << " :\t" << timeGPU * 1000 << " ms" << std::endl;

		if( (i + 1) < numGPUDevices)
		{
			//migrate the buffer to the queue which the kernel will be run.
			status = AESEncrypt_gpu[i + 1].enqueueMigrateMemObjects();
			CHECK_CL_ERROR(status, "enqueueMigrateMemObjects(single GPU) failed.");
		}
	}

	if(verify)
	{
		//Enqueue Read output buffer and verify results
		std::cout << "Verifying results for GPU: \n";

		for (int i = 0; i < numGPUDevices; i++ )
		{
			//read the result of each GPU
			status = AESEncrypt_gpu[i].enqueueReadData();
			CHECK_CL_ERROR(status , "Submitting Read buffer (single GPU) failed");

			std::cout << "GPU " << i << ": ";
			// Verify results
			AESEncrypt_gpu[i].verifyResults();
		}		
	}

	//Release the resources on all devices
	//Release context
	status = clReleaseContext(context);
	CHECK_CL_ERROR(status, "clCreateContext failed(single GPU).");

	//Release Program object
	status = clReleaseProgram(program);
	CHECK_CL_ERROR(status, "clReleaseProgram failed(single GPU).");

	//Release memory buffers
	status = clReleaseMemObject(inputBuffer);
	CHECK_CL_ERROR(status, "clReleaseMemObject failed(single GPU). (inputBuffer)");

	for (int i = 0; i < numGPUDevices ; i++)
	{
		//Release Kernel object, command-queue, event object
		status = clReleaseMemObject(AESEncrypt_gpu[i].outputBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject failed(single GPU). (outputBuffer)");

		status = clReleaseMemObject(AESEncrypt_gpu[i].rKeyBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

		status = clReleaseMemObject(AESEncrypt_gpu[i].sBoxBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

		status = clReleaseKernel(AESEncrypt_gpu[i].kernel);
		CHECK_CL_ERROR(status, "clReleaseCommandQueue(single GPU) failed.");

		status = clReleaseCommandQueue(AESEncrypt_gpu[i].queue);
		CHECK_CL_ERROR(status, "clReleaseCommandQueue(single GPU) failed.");

		status = clReleaseEvent(AESEncrypt_gpu[i].eventObject);
		CHECK_CL_ERROR(status, "clReleaseEvent(single GPU) failed.");
	}

	return SDK_SUCCESS;
}

//case 3: use multi GPU to compute
int runMultiGPU()
{
	int status;
	int device_id;

	//Setup for all GPU devices
	for(int i = 0; i < numGPUDevices; i++)
	{
		//Set the argument about AES encrypt
		status = AESEncrypt_gpu[i].setupAESEncryp();
		CHECK_CL_ERROR(status, "setupAESEncryp(CPU) failed.");

		//create the context for each GPU
		status = AESEncrypt_gpu[i].createContext();
		CHECK_CL_ERROR(status, "CreateContex(multi GPU) Failed.");

		//create the program for each GPU
		size_t sourceSize = strlen(source);
		status = AESEncrypt_gpu[i].createProgram(&source,&sourceSize);
		CHECK_CL_ERROR(status, "clCreateProgramWithSource(multi GPU) Failed.");

		//build the program for each GPU
		status = AESEncrypt_gpu[i].buildProgram();
		CHECK_CL_ERROR(status, "clBuildProgram(multi GPU) failed.");

		//create queue for each GPU
		status = AESEncrypt_gpu[i].createQueue();
		CHECK_CL_ERROR(status , "Creating Command Queue(multi GPU) failed");

		//create kernel for each GPU
		status = AESEncrypt_gpu[i].createKernel();
		CHECK_CL_ERROR(status , "Creating Kernel (multi GPU) failed");

		//create buffer for each GPU
		status = AESEncrypt_gpu[i].createBuffers();
		CHECK_CL_ERROR(status, "createBuffers(multi GPU) failed");

		//initialize the buffer for each GPU
		status = AESEncrypt_gpu[i].enqueueWriteBuffer();
		CHECK_CL_ERROR(status , "Submitting Write OpenCL Buffer (multi GPU) failed");

		//Set kernel arguments
		status = AESEncrypt_gpu[i].setKernelArgs();
		CHECK_CL_ERROR(status , "Setting Kernel Args(multi GPU) failed");
	}

	//Start a host timer here
	Timer gputime;
	gputime.createTimer();
	gputime.startTimer();

	status = workLoadBalance();
	CHECK_CL_ERROR(status ,  "workBalance failed");

	gputime.stopTimer();
	//Measure total time
	double totalTime = gputime.readTimer();

	//Print total time and individual times
	std::cout << "Total time : " << totalTime * 1000 << " ms" << std::endl;

	if(verify)
	{
		//merge the two output of GPU
		device_id = 0;
		cl_uchar* offsetPtr;
		int offset;

		for (int i = 0; i < GROUP; i++)
		{
			offset = i * NUM_GROUP_THREADS;
			std::vector<int>::iterator it=gpuId.begin();
			for (int j=0; j< i;j++)
			{
				it++;
			}
			device_id = *it;

			offsetPtr = &AESEncrypt_gpu[0].output[offset];

			status = clEnqueueReadBuffer(AESEncrypt_gpu[device_id].queue,
				subbufferOutput[i],
				CL_TRUE,
				0,
				NUM_GROUP_THREADS * sizeof(cl_uchar),
				offsetPtr, 
				0, 0, 0);
			CHECK_CL_ERROR(status, "clEnqueueReadBuffer failed.");
		}

		// Verify results
		std::cout << "Verifying results for multi GPU: ";
		AESEncrypt_gpu[0].verifyResults();
	}

	//Release the resources on all devices
	for (int i = 0; i < numGPUDevices; i++)
	{
		status = clReleaseContext(AESEncrypt_gpu[i].context);
		CHECK_CL_ERROR(status, "clCreateContext(multi GPU) failed.");

		status = clReleaseProgram(AESEncrypt_gpu[i].program);
		CHECK_CL_ERROR(status, "clReleaseProgram(multi GPU) failed.");

		status = clReleaseMemObject(AESEncrypt_gpu[i].inputBuffer);
		CHECK_CL_ERROR(status, "clReleaseMemObject(multi GPU) failed. (inputBuffer)");

		status = clReleaseMemObject(AESEncrypt_gpu[i].outputBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject(multi GPU) failed. (outputBuffer)");

		status = clReleaseMemObject(AESEncrypt_gpu[i].rKeyBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

		status = clReleaseMemObject(AESEncrypt_gpu[i].sBoxBuffer);
		CHECK_CL_ERROR(status,"clReleaseMemObject failed(CPU). (outputBuffer)");

		status = clReleaseKernel(AESEncrypt_gpu[i].kernel);
		CHECK_CL_ERROR(status, "clReleaseCommandQueue(multi GPU) failed.");

		status = clReleaseCommandQueue(AESEncrypt_gpu[i].queue);
		CHECK_CL_ERROR(status, "clReleaseCommandQueue(multi GPU) failed.");

		status = clReleaseEvent(AESEncrypt_gpu[i].eventObject);
		CHECK_CL_ERROR(status, "clReleaseEvent(multi GPU) failed.");
	}

	return SDK_SUCCESS;
}

//calls runCPU(), runSingleGPU() and runMultiGPU().
int run()
{
	if (numGPUDevices < 2)
	{
		std::cout << "Warning : There is only one GPU device detected. \n Use single GPU mode" << std::endl;
	}

	//case 1: Use single CPU to compute
	std::cout << sep<< "\nTest 1 : Single CPU\n"<<sep<<std::endl ;
	if (runCPU() != SDK_SUCCESS)
		return SDK_FAILURE;

	//case 2: Use single GPU to compute
	std::cout << sep<< "\nTest 2 : Single GPU\n"<<sep<<std::endl;
	if (runSingleGPU() != SDK_SUCCESS)
		return SDK_FAILURE;

	if (2 <= numGPUDevices)
	{
		//case 3: Use all GPU devices to compute
		std::cout << sep<<"\nTest 3 : multi  GPU\n" <<sep<<std::endl;
		std::cout<<"The total number of GPU:\t"<<numGPUDevices<<std::endl;

		if (runMultiGPU() != SDK_SUCCESS)
			return SDK_FAILURE;
	}

	return SDK_SUCCESS;
}

//work balance
int workLoadBalance()
{
	int status;
	int device_id;
	cl_buffer_region bufferRegion;

	//load balancing
	device_id = 0;
	subbufferInput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);
	subbufferOutput = (cl_mem *)malloc(sizeof(cl_mem) * GROUP);

	for (int i =0; i < numGPUDevices; i++)
	{
		AESEncrypt_gpu[i].eventStatus = CL_COMPLETE;
	}

	for(int i = 0; i < GROUP; i++)
	{
		//look for a available gpu
		while(AESEncrypt_gpu[device_id].eventStatus!= CL_COMPLETE)
		{
			device_id++;
			device_id %= numGPUDevices;    
			status = AESEncrypt_gpu[device_id].getEventInfo();
			CHECK_CL_ERROR(status, "GeEventInfo(multi GPU) Failed");	
		}

		bufferRegion.origin = i * NUM_GROUP_THREADS;
		bufferRegion.size = NUM_GROUP_THREADS;

		gpuId.push_back(device_id);

		subbufferInput[i] = clCreateSubBuffer(AESEncrypt_gpu[device_id].inputBuffer,
			CL_MEM_READ_ONLY, 
			CL_BUFFER_CREATE_TYPE_REGION, 
			(void *)&bufferRegion, &status);
		CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

		subbufferOutput[i] = clCreateSubBuffer(AESEncrypt_gpu[device_id].outputBuffer,
			CL_MEM_WRITE_ONLY, 
			CL_BUFFER_CREATE_TYPE_REGION, 
			(void *)&bufferRegion, &status);
		CHECK_CL_ERROR(status, "clCreateSubBuffer failed!");

		//Set kernel arguments
		status = clSetKernelArg(AESEncrypt_gpu[device_id].kernel, 0, sizeof(cl_mem), &subbufferOutput[i]);
		CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

		status = clSetKernelArg(AESEncrypt_gpu[device_id].kernel, 1, sizeof(cl_mem), &subbufferInput[i]);
		CHECK_CL_ERROR(status, "clSetKernelArg failed.(offset)");

		//run the kernel.
		status = AESEncrypt_gpu[device_id].enqueueKernel();
		CHECK_CL_ERROR(status, "enqueueKernel(multi GPU) failed.");

		device_id++;
		device_id %= numGPUDevices; 
	}

	for(int i =0; i < numGPUDevices; i++)
	{
		//wait for the running kernel complete
		status = AESEncrypt_gpu[i].waitForKernel();
		CHECK_CL_ERROR(status, "waitForKernel(multi GPU) Failed.");
	}

	return SDK_SUCCESS;
}

//Releases program's resources 
void cleanupHost()
{
	if(input != NULL)
	{
		free(input);
		input = NULL;
	}
	if(verificationOutput != NULL)
	{
		free(verificationOutput);
		verificationOutput = NULL;
	}
	if(AESEncrypt_cpu != NULL)
	{
		delete[]  AESEncrypt_cpu;
		AESEncrypt_cpu = NULL;
	}
	if(AESEncrypt_gpu != NULL)
	{
		delete[] AESEncrypt_gpu;
		AESEncrypt_gpu = NULL;
	}
}

int main(int argc, char * argv[])
{
	if (argc >= 6)
	{
		std::cout<<"Too many arguments. Type -h or --help for help.\n";
		exit(0);
	}
	for(int i = 1; i < argc; i++)
	{
		if(!strcmp(argv[i], "-e") || !strcmp(argv[i], "--verify"))
			verify = true;
		if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
		{
			printf("Usage:\n");
			printf("-h, --help\tPrint this help.\n");
			printf("-e, --verify\tVerify results against reference implementation.\n");
			exit(0);
		}
	}

	// Initialize Host application 
	if (initializeHost() != SDK_SUCCESS)
		return SDK_FAILURE;

	// Initialize OpenCL resources
	if ( initializeCL() != SDK_SUCCESS)
		return SDK_FAILURE;

	//calls runCPU(), runSingleGPU() and runMultiGPU()
	if (run() != SDK_SUCCESS)
		return SDK_FAILURE;

	// Release host resources
	cleanupHost();

	if(verify)
	{
		if (numGPUDevices >= 2)
		{
			requiredCount = numGPUDevices + 1;
		}
		else
		{
			requiredCount = numGPUDevices;
		}

		if(verificationCount != requiredCount)
		{
			std::cout << "FAILED!\n";
			return SDK_FAILURE;
		}
		else
		{
			std::cout << "PASSED!\n" ;
			return SDK_SUCCESS;
		}
	}
}
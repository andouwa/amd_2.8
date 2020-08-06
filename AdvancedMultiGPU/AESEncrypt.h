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
#ifndef AESENCRYPT_H
#define AESENCRYPT_H

#include "device.h"
#include <string.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>

#include <CL/opencl.h>


class AESEncrypt:public Device
{
public:

	//CL Objects and memory buffers
	int status;
	cl_uchar*		output;
	cl_mem       rKeyBuffer;  
	cl_mem       sBoxBuffer;

	cl_uint      keySizeBits;
	cl_uint      keySize;
	cl_uint      explandedKeySize;
	cl_uint      rounds;

	cl_uchar      *key;              // Encryption Key 
	cl_uchar      *expandedKey;      //Encryption Key after expanding
	cl_uchar      *roundKey;         // Encryption Key after expanding rounded

	AESEncrypt();
	//~AESEncrypt();

	//Create context
	int createContext();

	//Create command queue
	int createQueue();

	//Create buffer objects
	int createBuffers();

	//Write buffer into kernel
	int enqueueWriteBuffer();

	//Create program object
	int createProgram(const char **source, const size_t *sourceSize);

	//Build program objects
	int buildProgram();

	//Create kernel objects
	int createKernel();

	//Set arguments for kernel
	int setKernelArgs();

	//Migrate memory objects between different devices
	int enqueueMigrateMemObjects();

	//Execute kernel
	int enqueueKernel();

	//Waite for kernel to be complete
	int waitForKernel();

	//Get the running time of the kernel
	int getKernelTime();

	//Read the result data to Host
	int enqueueReadData();

	//Check the results
	int verifyResults();

	//Query the command queue status
	int  getEventInfo();

	//Clean up the resources
	int cleanupResources();	

		//setup AES 
	int setupAESEncryp();

    /* encrypt functions  */
    void mixColumns(cl_uchar * state);
    void subBytes(cl_uchar * state);
    void addRoundKey(cl_uchar * state, cl_uchar * roundKey);
    void shiftRows(cl_uchar * state);
    cl_uchar galoisMultiplication(cl_uchar a, cl_uchar b);

    void aesMain(cl_uchar * state, cl_uchar * expandedKey, cl_uint rounds);
    void aesRound(cl_uchar * state, cl_uchar * roundKey);
    void mixColumn(cl_uchar *column);
    void shiftRow(cl_uchar * state, cl_uchar nbr);
    cl_uchar getSBoxValue(cl_uint num);

    /* key generation functions */
    void createRoundKey(cl_uchar * expandedKey, cl_uchar * roundKey);
    cl_uchar getRconValue(cl_uint num);
    void rotate(cl_uchar * word);
    void core(cl_uchar * word, cl_uint iter);
    void keyExpansion(cl_uchar * key, cl_uchar * expandedKey,
										cl_uint keySize, cl_uint explandedKeySize);
};

// Read a file into a string
std::string convertToString(const char * filename);

int initializeCL();
//calls runCPU(), runSingleGPU() and runMultiGPU().
int initializeHost();

int run();


//case 1: Use single CPU to compute
int runCPU();

//case 2: Use single GPU to compute
int runSingleGPU();

//case 3: Use all GPU devices to compute
int runMultiGPU();

//work balance 
int workLoadBalance();

// Releases program's resources
void cleanupHost(void);

#endif

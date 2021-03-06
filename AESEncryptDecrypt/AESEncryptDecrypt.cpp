/**********************************************************************
Copyright �2012 Advanced Micro Devices, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

�	Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
�	Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************/

#include "AESEncryptDecrypt.hpp"

using namespace AES;

unsigned char
	galoisMultiplication(unsigned char a, 
	unsigned char b)
{
	unsigned char p = 0; 
	for(unsigned int i = 0; i < 8; ++i)
	{
		if((b & 1) == 1)
		{
			p ^= a;
		}
		unsigned char hiBitSet = (a & 0x80);
		a <<= 1;
		if(hiBitSet == 0x80)
		{
			a ^= 0x1b;
		}
		b >>= 1;
	}
	return p;
}

void createEncryptTable(unsigned char* table)
{
	for(unsigned int a=0; a<256; ++a)
	{
		table[a]=galoisMultiplication((unsigned char)a,1);
		table[a + 256]=galoisMultiplication((unsigned char)a,2);
		table[a + 512]=galoisMultiplication((unsigned char)a,3);
	}
}

void createDecryptTable(unsigned char* table)
{
	for(unsigned int a=0; a<256; ++a)
	{
		table[a]=galoisMultiplication((unsigned char)a,14);
		table[a + 256]=galoisMultiplication((unsigned char)a,11);
		table[a + 512]=galoisMultiplication((unsigned char)a,13);
		table[a + 768]=galoisMultiplication((unsigned char)a, 9);
	}
}


int AESEncryptDecrypt::setupAESEncryptDecrypt()
{
    numChannels = image.getNumChannels();

    width = width * numChannels;

    cl_uint sizeBytes = width * height * sizeof(cl_uchar);

    input = (cl_uchar*)malloc(sizeBytes);
    CHECK_ALLOCATION(input, "Failed to allocate host memory. (input)");

    cl_uint j = 0; 
    for (int i = 0; i < height * (width / numChannels); i++)
    {
        input[j++] = pixels[i].x;
        input[j++] = pixels[i].y;
        input[j++] = pixels[i].z;
    }

    // 1 Byte = 8 bits 
    keySize = keySizeBits/8;
    // due to unknown represenation of cl_uchar 
    keySizeBits = keySize * sizeof(cl_uchar); 
    key = (cl_uchar*)malloc(keySizeBits);
    CHECK_ALLOCATION(key, "Failed to allocate memory(key)");

    // random initialization of key 
    sampleCommon->fillRandom<cl_uchar>(key, keySize, 1, 0, 255, seed); 

    // expand the key 
    explandedKeySize = (rounds + 1) * keySize;
    
    expandedKey = (cl_uchar*)malloc(explandedKeySize * sizeof(cl_uchar));
    CHECK_ALLOCATION(expandedKey, "Failed to allocate memory(expandedKey)");

    roundKey    = (cl_uchar*)malloc(explandedKeySize * sizeof(cl_uchar));
    CHECK_ALLOCATION(roundKey, "Failed to allocate memory(roundKey)");

    keyExpansion(key, expandedKey, keySize, explandedKeySize);
    for(cl_uint i = 0; i < rounds + 1; ++i)
    {
        createRoundKey(expandedKey + keySize * i, roundKey + keySize * i);
    }

    output = (cl_uchar*)malloc(sizeBytes);
    CHECK_ALLOCATION(output, "Failed to allocate host memory. (output)");

    if(!quiet) 
    {
        if(decrypt)
        {
            std::cout << "Decrypting Image ...." << std::endl;
        }
        else
        {
            std::cout << "Encrypting Image ...." << std::endl;
        }

        std::cout << "Input Image : " << inFilename << std::endl;
        std::cout << "Key : ";
        for(cl_uint i = 0; i < keySize; ++i)
        {
            std::cout << (cl_uint)key[i] << " ";
        }
        std::cout << std::endl;
    }
    return SDK_SUCCESS;
}

void
AESEncryptDecrypt::convertColorToGray(const uchar4 *pixels, cl_uchar *gray)
{
    for(cl_int i = 0; i < height; ++i)
        for(cl_int j = 0; j < width; ++j)
        {
            cl_uint index = i * width + j;
            // gray = (0.3 * R + 0.59 * G + 0.11 * B)
            gray[index] = cl_uchar (pixels[index].x * 0.3  + 
                                    pixels[index].y * 0.59 + 
                                    pixels[index].z * 0.11 );
        }
}

void
AESEncryptDecrypt::convertGrayToGray(const uchar4 *pixels, cl_uchar *gray)
{
    for(cl_int i = 0; i < height; ++i)
        for(cl_int j = 0; j < width; ++j)
        {
            cl_uint index = i * width + j;
            gray[index] = pixels[index].x;
        }
}

void
AESEncryptDecrypt::convertGrayToPixels(const cl_uchar *gray, uchar4 *pixels)
{
    for(cl_int i = 0; i < height; ++i)
        for(cl_int j = 0; j <width; ++j)
        {
            cl_uint index = i * width + j;
            pixels[index].x = gray[index];
            pixels[index].y = gray[index];
            pixels[index].z = gray[index];
        }
}

int 
AESEncryptDecrypt::genBinaryImage()
{
    streamsdk::bifData binaryData;
    binaryData.kernelName = std::string("AESEncryptDecrypt_Kernels.cl");
    binaryData.flagsStr = std::string("");
    if(isComplierFlagsSpecified())
        binaryData.flagsFileName = std::string(flags.c_str());

    binaryData.binaryName = std::string(dumpBinary.c_str());
    int status = sampleCommon->generateBinaryImage(binaryData);
    return status;
}


int
AESEncryptDecrypt::setupCL(void)
{
    cl_int status = 0;
    cl_device_type dType;
    
    if(deviceType.compare("cpu") == 0)
    {
        dType = CL_DEVICE_TYPE_CPU;
    }
    else //deviceType = "gpu" 
    {
        dType = CL_DEVICE_TYPE_GPU;
        if(isThereGPU() == false)
        {
            std::cout << "GPU not found. Falling back to CPU device" << std::endl;
            dType = CL_DEVICE_TYPE_CPU;
        }
    }

    /*
     * Have a look at the available platforms and pick either
     * the AMD one if available or a reasonable default.
     */
    cl_platform_id platform = NULL;
    int retValue = sampleCommon->getPlatform(platform, platformId, isPlatformEnabled());
    CHECK_ERROR(retValue, SDK_SUCCESS, "sampleCommon::getPlatform() failed");

    // Display available devices.
    retValue = sampleCommon->displayDevices(platform, dType);
    CHECK_ERROR(retValue, SDK_SUCCESS, "sampleCommon::displayDevices() failed");

    /*
     * If we could find our platform, use it. Otherwise use just available platform.
     */
    cl_context_properties cps[3] = 
    {
        CL_CONTEXT_PLATFORM, 
        (cl_context_properties)platform, 
        0
    };

    context = clCreateContextFromType(
                  cps,
                  dType,
                  NULL,
                  NULL,
                  &status);
    CHECK_OPENCL_ERROR(status, "clCreateContextFromType failed.");

    // getting device on which to run the sample
    status = sampleCommon->getDevices(context, &devices, deviceId, isDeviceIdEnabled());
    CHECK_ERROR(status, SDK_SUCCESS, "sampleCommon::getDevices() failed");

    {
        // The block is to move the declaration of prop closer to its use
        cl_command_queue_properties prop = 0;
        commandQueue = clCreateCommandQueue(
                context, 
                devices[deviceId], 
                prop, 
                &status);
        CHECK_OPENCL_ERROR( status, "clCreateCommandQueue failed.");
    }

    //Set device info of given cl_device_id
    retValue = deviceInfo.setDeviceInfo(devices[deviceId]);
    CHECK_ERROR(retValue, 0, "SDKDeviceInfo::setDeviceInfo() failed");

    // Set Presistent memory only for AMD platform
    cl_mem_flags inMemFlags = CL_MEM_READ_ONLY;
    if(isAmdPlatform())
        inMemFlags |= CL_MEM_USE_PERSISTENT_MEM_AMD;

    inputBuffer = clCreateBuffer(
                    context, 
                    inMemFlags,
                    sizeof(cl_uchar ) * width * height,
                    NULL, 
                    &status);
    CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (inputBuffer)");

    outputBuffer = clCreateBuffer(
                    context, 
                    CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
                    sizeof(cl_uchar ) * width * height,
                    NULL, 
                    &status);
    CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (outputBuffer)");

    rKeyBuffer = clCreateBuffer(
                    context, 
                    CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                    sizeof(cl_uchar ) * explandedKeySize,
                    roundKey,
                    &status);
    CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (rKeyBuffer)");

    cl_uchar * sBox;
    sBox = (cl_uchar *)sbox;
    sBoxBuffer = clCreateBuffer(
                    context, 
                    CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                    sizeof(cl_uchar ) * 256,
                    sBox,
                    &status);
    CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (sBoxBuffer)");

    cl_uchar * rsBox;
    rsBox = (cl_uchar *)rsbox;
    rsBoxBuffer = clCreateBuffer(
                    context, 
                    CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                    sizeof(cl_uchar ) * 256,
                    rsBox,
                    &status);
    CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (sBoxBuffer)");
   
	unsigned char encryptTable[256*3];
	createEncryptTable(encryptTable);

	encryptTableBuffer = clCreateBuffer(
		context,
		 CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		 sizeof(cl_uchar ) * 256*3,
		 encryptTable,
		 &status
		 );
	CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (encryptTable)");

	unsigned char decryptTable[256*4];
	createDecryptTable(decryptTable);
	decryptTableBuffer = clCreateBuffer(
		context,
		CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		sizeof(cl_uchar ) * 256*4,
		decryptTable,
		&status
		);
	CHECK_OPENCL_ERROR(status, "clCreateBuffer failed. (decryptTable)");

    // create a CL program using the kernel source 
    streamsdk::buildProgramData buildData;
    buildData.kernelName = std::string("AESEncryptDecrypt_Kernels.cl");
    buildData.devices = devices;
    buildData.deviceId = deviceId;
    buildData.flagsStr = std::string("");
    if(isLoadBinaryEnabled())
        buildData.binaryName = std::string(loadBinary.c_str());

    if(isComplierFlagsSpecified())
        buildData.flagsFileName = std::string(flags.c_str());

    retValue = sampleCommon->buildOpenCLProgram(program, context, buildData);
    CHECK_ERROR(retValue, 0, "sampleCommon::buildOpenCLProgram() failed");

    /* get a kernel object handle for a kernel with the given name */
    if(decrypt)
    {
        kernel = clCreateKernel(program, "AESDecrypt", &status);
    }
    else
    {
        kernel = clCreateKernel(program, "AESEncrypt", &status);
    }
    CHECK_OPENCL_ERROR(status, "clCreateKernel failed.");

    return SDK_SUCCESS;
}




int 
AESEncryptDecrypt::runCLKernels(void)
{
    cl_int   status;
    cl_int eventStatus = CL_QUEUED;
    
    size_t globalThreads[2] = {width / 4, height};
    size_t localThreads[2] = {64, 4};

    if (localThreads[1] != 4)
    {
        std::cout << "localThreads[1] value should be 4 \n";
        return SDK_FAILURE;
    }

    status = kernelInfo.setKernelWorkGroupInfo(kernel, devices[deviceId]);
    CHECK_ERROR(status, SDK_SUCCESS, "KernelInfo.setKernelWorkGroupInfo() failed");

    availableLocalMemory = deviceInfo.localMemSize - kernelInfo.localMemoryUsed; 

    neededLocalMemory  = 2 * localThreads[0] * localThreads[1] * 4;

    if(neededLocalMemory > availableLocalMemory)
    {
        std::cout << "Unsupported: Insufficient local memory on device." << std::endl;
        return SDK_SUCCESS;
    }

    if((cl_uint)(localThreads[0] * localThreads[1]) > kernelInfo.kernelWorkGroupSize )
    {
        localThreads[0] = kernelInfo.kernelWorkGroupSize / 4;
    }

    
    if(localThreads[0] > deviceInfo.maxWorkItemSizes[0] ||
       localThreads[1] > deviceInfo.maxWorkItemSizes[1] ||
       localThreads[0] * localThreads[1] > deviceInfo.maxWorkGroupSize)
    {
        std::cout << "Unsupported: Device does not support requested number of work items."<<std::endl;
        return SDK_SUCCESS;
    }
 
    cl_event writeEvt;
    status = clEnqueueWriteBuffer(
                commandQueue,
                inputBuffer,
                CL_FALSE,
                0,
                sizeof(cl_uchar ) * width * height,
                input,
                0,
                NULL,
                &writeEvt);
    CHECK_OPENCL_ERROR(status, "clEnqueueWriteBuffer failed. (inputBuffer)");

    status = clFlush(commandQueue);
    CHECK_OPENCL_ERROR(status, "clFlush failed.");

    status = sampleCommon->waitForEventAndRelease(&writeEvt);
    CHECK_ERROR(status, SDK_SUCCESS, "WaitForEventAndRelease(writeEvt) Failed");

	cl_uint arc=0;
    // Set appropriate arguments to the kernel
    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    sizeof(cl_mem), 
                    (void *)&outputBuffer);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (outputBuffer)");

    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    sizeof(cl_mem), 
                    (void *)&inputBuffer);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (inputBuffer)");

    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    sizeof(cl_mem), 
                    (void *)&rKeyBuffer);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (rKeyBuffer)");

    if(decrypt)
    {
        status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    sizeof(cl_mem), 
                    (void *)&rsBoxBuffer);
		CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (SBoxBuffer)");

		status = clSetKernelArg(
			kernel, 
			arc++, 
			sizeof(cl_mem), 
			(void *)&decryptTableBuffer);
		CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (mulTableBuffer)");

    }
    else
    {
		status = clSetKernelArg(
			kernel, 
			arc++, 
			sizeof(cl_mem), 
			(void *)&sBoxBuffer);

		CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (SBoxBuffer)");

		status = clSetKernelArg(
			kernel, 
			arc++, 
			sizeof(cl_mem), 
			(void *)&encryptTableBuffer);
		CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (mulTableBuffer)");
	}	

	

    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    localThreads[0] * localThreads[1] * 4 * sizeof (cl_uchar), 
                    NULL);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (block0)");

    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    localThreads[0] * localThreads[1] * 4 * sizeof(cl_uchar), 
                    NULL);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (block1)");

    status = clSetKernelArg(
                    kernel, 
                    arc++, 
                    sizeof(cl_uint), 
                    (void *)&width);
    CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (width)");

	status = clSetKernelArg(
		kernel, 
		arc++, 
		sizeof(cl_uint), 
		(void *)&rounds);
	CHECK_OPENCL_ERROR(status, "clSetKernelArg failed. (rounds)");

    /* 
     * Enqueue a kernel run call.
     */
    cl_event ndrEvt;
    status = clEnqueueNDRangeKernel(
            commandQueue,
            kernel,
            2,
            NULL,
            globalThreads,
            localThreads,
            0,
            NULL,
            &ndrEvt);
    CHECK_OPENCL_ERROR(status, "clEnqueueNDRangeKernel failed.");

    status = clFlush(commandQueue);
    CHECK_OPENCL_ERROR(status, "clFlush failed.");

    status = sampleCommon->waitForEventAndRelease(&ndrEvt);
    CHECK_ERROR(status, SDK_SUCCESS, "WaitForEventAndRelease(ndrEvt) Failed");

    /* Enqueue the results to application pointer*/
    cl_event readEvt;
    status = clEnqueueReadBuffer(
                commandQueue,
                outputBuffer,
                CL_FALSE,
                0,
                width * height * sizeof(cl_uchar),
                output,
                0,
                NULL,
                &readEvt);
    CHECK_OPENCL_ERROR(status, "clEnqueueReadBuffer failed.");

    status = clFlush(commandQueue);
    CHECK_OPENCL_ERROR(status, "clFlush failed.");

    status = sampleCommon->waitForEventAndRelease(&readEvt);
    CHECK_ERROR(status, SDK_SUCCESS, "WaitForEventAndRelease(readEvt) Failed");
    return SDK_SUCCESS;
}

cl_uchar 
AESEncryptDecrypt::getRconValue(cl_uint num)
{
    return Rcon[num];
}

void
AESEncryptDecrypt::rotate(cl_uchar * word)
{
    cl_uchar c = word[0];
    for(cl_uint i = 0; i < 3; ++i)
    {
        word[i] = word[i + 1];
    }
    word[3] = c;
}

void
AESEncryptDecrypt::core(cl_uchar * word, cl_uint iter)
{
    rotate(word);
    for(cl_uint i = 0; i < 4; ++i)
    {
        word[i] = getSBoxValue(word[i]);
    }
    word[0] = word[0] ^ getRconValue(iter);
}

void
AESEncryptDecrypt::keyExpansion(cl_uchar * key, cl_uchar * expandedKey,
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

cl_uchar 
AESEncryptDecrypt::getSBoxValue(cl_uint num)
{
    return sbox[num];
}

cl_uchar 
AESEncryptDecrypt::getSBoxInvert(cl_uint num)
{
    return rsbox[num];
}

cl_uchar
AESEncryptDecrypt::galoisMultiplication(cl_uchar a, cl_uchar b)
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

void
AESEncryptDecrypt::mixColumn(cl_uchar *column)
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

void
AESEncryptDecrypt::mixColumnInv(cl_uchar *column)
{
    cl_uchar cpy[4];
    for(cl_uint i = 0; i < 4; ++i)
    {
        cpy[i] = column[i];
    }
    column[0] = galoisMultiplication(cpy[0], 14 )^
                galoisMultiplication(cpy[3], 9 )^
                galoisMultiplication(cpy[2], 13)^
                galoisMultiplication(cpy[1], 11);
    
    column[1] = galoisMultiplication(cpy[1], 14 )^
                galoisMultiplication(cpy[0], 9 )^
                galoisMultiplication(cpy[3], 13)^
                galoisMultiplication(cpy[2], 11);
    
    column[2] = galoisMultiplication(cpy[2], 14 )^
                galoisMultiplication(cpy[1], 9 )^
                galoisMultiplication(cpy[0], 13)^
                galoisMultiplication(cpy[3], 11);
    
    column[3] = galoisMultiplication(cpy[3], 14 )^
                galoisMultiplication(cpy[2], 9 )^
                galoisMultiplication(cpy[1], 13)^
                galoisMultiplication(cpy[0], 11);
}

void
AESEncryptDecrypt::mixColumns(cl_uchar * state, cl_bool inverse)
{
    cl_uchar column[4];
    for(cl_uint i = 0; i < 4; ++i)
    {
        for(cl_uint j = 0; j < 4; ++j)
        {
            column[j] = state[j * 4 + i];
        }
        
        if(inverse)
        {
            mixColumnInv(column);
        }
        else
        {
            mixColumn(column);
        }
       
         for(cl_uint j = 0; j < 4; ++j)
        {
            state[j * 4 + i] = column[j];
        }
    }
}

void
AESEncryptDecrypt::subBytes(cl_uchar * state, cl_bool inverse)
{
    for(cl_uint i = 0; i < keySize; ++i)
    {
        state[i] = inverse ? getSBoxInvert(state[i]): getSBoxValue(state[i]);
    }
}

void
AESEncryptDecrypt::shiftRow(cl_uchar *state, cl_uchar nbr)
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

void
AESEncryptDecrypt::shiftRowInv(cl_uchar *state, cl_uchar nbr)
{
    for(cl_uint i = 0; i < nbr; ++i)
    {
        cl_uchar tmp = state[3];
        for(cl_uint j = 3; j > 0; --j)
        {
            state[j] = state[j - 1];
        }
        state[0] = tmp;
    }
}

void
AESEncryptDecrypt::shiftRows(cl_uchar * state, cl_bool inverse)
{
    for(cl_uint i = 0; i < 4; ++i)
    {
        if(inverse)
            shiftRowInv(state + i * 4, i);
        else
            shiftRow(state + i * 4, i);
    }
}

void
AESEncryptDecrypt::addRoundKey(cl_uchar * state, cl_uchar * rKey)
{
    for(cl_uint i = 0; i < keySize; ++i)
    {
        state[i] = state[i] ^ rKey[i];
    }
}

void
AESEncryptDecrypt::createRoundKey(cl_uchar * eKey, cl_uchar * rKey)
{
    for(cl_uint i = 0; i < 4; ++i)
        for(cl_uint j = 0; j < 4; ++j)
        {
            rKey[i + j * 4] = eKey[i * 4 + j];
        }
}

void
AESEncryptDecrypt::aesRound(cl_uchar * state, cl_uchar * rKey)
{
    subBytes(state, decrypt);
    shiftRows(state, decrypt);
    mixColumns(state, decrypt);
    addRoundKey(state, rKey);
}

void
AESEncryptDecrypt::aesMain(cl_uchar * state, cl_uchar * rKey, cl_uint rounds)
{
    addRoundKey(state, rKey);

    for(cl_uint i = 1; i < rounds; ++i)
    {
        aesRound(state, rKey + keySize*i);
    }

    subBytes(state, decrypt);
    shiftRows(state, decrypt);
    addRoundKey(state, rKey + keySize*rounds);
}

void
AESEncryptDecrypt::aesRoundInv(cl_uchar * state, cl_uchar * rKey)
{
    shiftRows(state, decrypt);
    subBytes(state, decrypt);
    addRoundKey(state, rKey);
    mixColumns(state, decrypt);
}

void
AESEncryptDecrypt::aesMainInv(cl_uchar * state, cl_uchar * rKey, cl_uint rounds)
{
    addRoundKey(state, rKey + keySize * rounds);
    for(cl_uint i = rounds - 1; i > 0; --i)
    {
        aesRoundInv(state, rKey + keySize*i);
    } 
    shiftRows(state, decrypt);
    subBytes(state, decrypt);
    addRoundKey(state, rKey);
}

void 
AESEncryptDecrypt::AESEncryptDecryptCPUReference(cl_uchar * output       ,
                                                 cl_uchar * input        ,
                                                 cl_uchar * rKey         ,
                                                 cl_uint explandedKeySize,
                                                 cl_uint width           ,
                                                 cl_uint height          ,
                                                 cl_bool inverse         )
{
    cl_uchar block[16];
   
    for(cl_uint blocky = 0; blocky < height / 4; ++blocky)
        for(cl_uint blockx = 0; blockx < width / 4; ++blockx)
        { 
            for(cl_uint i = 0; i < 4; ++i)
            {
                for(cl_uint j = 0; j < 4; ++j)
                {
                    cl_uint x = blockx * 4 + j;
                    cl_uint y = blocky * 4 + i;
                    cl_uint index = y * width + x;
                    block[i * 4 + j] = input[index];
                }
            }

            if(inverse)
                aesMainInv(block, rKey, rounds);
            else
                aesMain(block, rKey, rounds);
            
            for(cl_uint i = 0; i < 4 ; ++i)
            {
                for(cl_uint j = 0; j < 4; ++j)
                {
                    cl_uint x = blockx * 4 + j;
                    cl_uint y = blocky * 4 + i;
                    cl_uint index = y * width + x;
                    output[index] =  block[i * 4 + j];
                } 
            }
        }
}


int 
AESEncryptDecrypt::initialize()
{
   // Call base class Initialize to get default configuration
   if(this->SDKSample::initialize())
      return SDK_FAILURE;

    iterations = 1000;
    timing =1 ;
    verify =1;


   streamsdk::Option* ifilename_opt = new streamsdk::Option;
   CHECK_ALLOCATION(ifilename_opt, "Memory allocation error.\n");

   ifilename_opt->_sVersion = "x";
   ifilename_opt->_lVersion = "input";
   ifilename_opt->_description = "Image as Input";
   ifilename_opt->_type = streamsdk::CA_ARG_STRING;
   ifilename_opt->_value = &inFilename;
   sampleArgs->AddOption(ifilename_opt);

   delete ifilename_opt;

   streamsdk::Option* ofilename_opt = new streamsdk::Option;
   CHECK_ALLOCATION(ofilename_opt, "Memory allocation error.\n");

   ofilename_opt->_sVersion = "y";
   ofilename_opt->_lVersion = "output";
   ofilename_opt->_description = "Image as Ouput";
   ofilename_opt->_type = streamsdk::CA_ARG_STRING;
   ofilename_opt->_value = &outFilename;
   sampleArgs->AddOption(ofilename_opt);

   delete ofilename_opt;


    streamsdk::Option* decrypt_opt = new streamsdk::Option;
    CHECK_ALLOCATION(decrypt_opt, "Memory allocation error.\n"); 

    decrypt_opt->_sVersion = "z";
    decrypt_opt->_lVersion = "decrypt";
    decrypt_opt->_description = "Decrypt the Input Image"; 
    decrypt_opt->_type     = streamsdk::CA_NO_ARGUMENT;
    decrypt_opt->_value    = &decrypt;
    sampleArgs->AddOption(decrypt_opt);

    delete decrypt_opt;

    streamsdk::Option* num_iterations = new streamsdk::Option;
    CHECK_ALLOCATION(num_iterations, "Memory allocation error.\n");

    num_iterations->_sVersion = "i";
    num_iterations->_lVersion = "iterations";
    num_iterations->_description = "Number of iterations for kernel execution";
    num_iterations->_type = streamsdk::CA_ARG_INT;
    num_iterations->_value = &iterations;

    sampleArgs->AddOption(num_iterations);

    delete num_iterations;

    return SDK_SUCCESS;
}

int 
AESEncryptDecrypt::setup()
{
    std::string filePath = sampleCommon->getPath() + inFilename;
    image.load(filePath.c_str());

    width  = image.getWidth();
    height = image.getHeight();

	if(iterations < 1)
	{
		std::cout<<"Error, iterations cannot be 0 or negative. Exiting..\n";
		exit(0);
	}
    // check condition for the bitmap to be initialized
    if(width<0 || height <0)
        return SDK_FAILURE;

    pixels = image.getPixels(); 

    if(setupAESEncryptDecrypt() != SDK_SUCCESS)
      return SDK_FAILURE;
    
    int timer = sampleCommon->createTimer();
    sampleCommon->resetTimer(timer);
    sampleCommon->startTimer(timer);

    if(setupCL()!= SDK_SUCCESS)
      return SDK_FAILURE;

    sampleCommon->stopTimer(timer);

    setupTime = (double)(sampleCommon->readTimer(timer));

    return SDK_SUCCESS;
}


int 
AESEncryptDecrypt::run()
{
    for(int i = 0; i < 2 && iterations != 1; i++)
    {
        // Arguments are set and execution call is enqueued on command buffer
        if(runCLKernels() != SDK_SUCCESS)
            return SDK_FAILURE;
    }

    int timer = sampleCommon->createTimer();
    sampleCommon->resetTimer(timer);
    sampleCommon->startTimer(timer);

    std::cout << "Executing kernel for " << iterations << 
        " iterations" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;

    for(int i = 0; i < iterations; i++)
    {
        // Arguments are set and execution call is enqueued on command buffer
        if(runCLKernels()!=SDK_SUCCESS)
            return SDK_FAILURE;
    }

    sampleCommon->stopTimer(timer);
    averageKernelTime = (double)(sampleCommon->readTimer(timer)) / iterations;
    
    //XXX: Write output to an output Image

    cl_uint j = 0;

    for (int i = 0; i < height * width; i += numChannels)
    {
        pixels[j].x = output[i];
        pixels[j].y = output[i + 1];
        pixels[j].z = output[i + 2];
        pixels[j].w = 255;
        j++;
    }

    image.write(outFilename.c_str());
    
    streamsdk::SDKBitMap temp; 
    temp.load(outFilename.c_str());

    uchar4 *tempPixels = temp.getPixels();

    if(!quiet) {
        std::cout << "Output Filename : " << outFilename << std::endl;
    }
    
    return SDK_SUCCESS;
}

int 
AESEncryptDecrypt::verifyResults()
{
    if (verify && !decrypt)
    {
        verificationOutput = (cl_uchar *) malloc(width * height * sizeof(cl_uchar));
        CHECK_ALLOCATION(verificationOutput, "Failed to allocate host memory. (verificationOutput)");

        /* 
         * reference implementation
         */
        int refTimer = sampleCommon->createTimer();
        sampleCommon->resetTimer(refTimer);
        sampleCommon->startTimer(refTimer);
        AESEncryptDecryptCPUReference(verificationOutput, input, roundKey, explandedKeySize, 
                                                                width, height, decrypt);
        sampleCommon->stopTimer(refTimer);
        referenceKernelTime = sampleCommon->readTimer(refTimer);

        // compare the results and see if they match
        if(memcmp(output, verificationOutput, height*width*sizeof(cl_uchar)) == 0)
        {
            std::cout<<"Encryption Passed!\n" << std::endl;

            if (cleanup() != SDK_SUCCESS)
            {
                return SDK_FAILURE;
            }

            printStats();

            decrypt = true;
            char tempOutFilename[256];
            
            std::string tempInputFilename = inFilename.substr(0, (inFilename.length() - 4));
            sprintf(tempOutFilename, "%s_result.bmp", tempInputFilename.c_str());
            inFilename.assign(outFilename);
            outFilename.assign(tempOutFilename);

            seed = 123;
            input  = NULL;
            output = NULL;
            key    = NULL;
            verificationOutput = NULL;
            keySizeBits = 128;
            rounds = 10;
            setupTime = 0;
            averageKernelTime = 0;
            iterations = 1;

            if (setup() != SDK_SUCCESS)
            {
                return SDK_FAILURE;
            }

            if (run()!=SDK_SUCCESS)
            {
                return SDK_FAILURE;
            }

            if (verifyResults() != SDK_SUCCESS)
            {
                return SDK_FAILURE;
            }
            
            return SDK_SUCCESS;
        }
        else
        {  
            std::cout<<"Encryption Failed\n" << std::endl;
            return SDK_FAILURE;
        }
    }
    else if(verify && decrypt)
    {
        verificationOutput = (cl_uchar *) malloc(width * height * sizeof(cl_uchar));
        CHECK_ALLOCATION(verificationOutput, "Failed to allocate host memory. (verificationOutput)");

        /* 
         * reference implementation
         */
        int refTimer = sampleCommon->createTimer();
        sampleCommon->resetTimer(refTimer);
        sampleCommon->startTimer(refTimer);
        AESEncryptDecryptCPUReference(verificationOutput, input, roundKey, explandedKeySize, 
                                                                width, height, decrypt);
        sampleCommon->stopTimer(refTimer);
        referenceKernelTime = sampleCommon->readTimer(refTimer);

        // compare the results and see if they match
        if(memcmp(output, verificationOutput, height * width * sizeof(cl_uchar)) == 0)
        {
            std::cout<<"Decryption Passed!\n" << std::endl;
            return SDK_SUCCESS;
        }
        else
        {  
            std::cout<<"Decryption Failed\n" << std::endl;
            return SDK_FAILURE;
        }
    }

    return SDK_SUCCESS;
}

void AESEncryptDecrypt::printStats()
{
    std::string strArray[4] = {"Width", "Height", "Time(sec)", "[Transfer+Kernel]Time(sec)"};
    std::string stats[4];

    totalTime = setupTime + (averageKernelTime * iterations);
    
    stats[0] = sampleCommon->toString(width    , std::dec);
    stats[1] = sampleCommon->toString(height   , std::dec);
    stats[2] = sampleCommon->toString(totalTime, std::dec);
    stats[3] = sampleCommon->toString(averageKernelTime, std::dec);

    this->SDKSample::printStats(strArray, stats, 4);
}

int AESEncryptDecrypt::cleanup()
{
    // Releases OpenCL resources (Context, Memory etc.)
    cl_int status;

    status = clReleaseKernel(kernel);
    CHECK_OPENCL_ERROR(status, "clReleaseKernel failed.");

    status = clReleaseProgram(program);
    CHECK_OPENCL_ERROR(status, "clReleaseProgram failed.");
 
    status = clReleaseMemObject(inputBuffer);
    CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

    status = clReleaseMemObject(outputBuffer);
    CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

    status = clReleaseMemObject(rKeyBuffer);
    CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

    status = clReleaseMemObject(sBoxBuffer);
    CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

    status = clReleaseMemObject(rsBoxBuffer);
    CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

	status = clReleaseMemObject(encryptTableBuffer);
	CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

	status = clReleaseMemObject(decryptTableBuffer);
	CHECK_OPENCL_ERROR(status, "clReleaseMemObject failed.");

    status = clReleaseCommandQueue(commandQueue);
    CHECK_OPENCL_ERROR(status, "clReleaseCommandQueue failed.");

    status = clReleaseContext(context);
    CHECK_OPENCL_ERROR(status, "clReleaseContext failed.");

    // release program resources (input memory etc.)
    FREE(input);
    
    FREE(key);
    
    FREE(expandedKey);
    
    FREE(roundKey);

    FREE(output);

    FREE(verificationOutput);

    FREE(devices);

    return SDK_SUCCESS;
}

int 
main(int argc, char * argv[])
{
    AESEncryptDecrypt clAESEncryptDecrypt("OpenCL AES Encrypt Decrypt");

    if(clAESEncryptDecrypt.initialize() != SDK_SUCCESS)
        return SDK_FAILURE;
    if(clAESEncryptDecrypt.parseCommandLine(argc, argv))
        return SDK_FAILURE;

    if(clAESEncryptDecrypt.isDumpBinaryEnabled())
    {
        return clAESEncryptDecrypt.genBinaryImage();
    }
    
    if(clAESEncryptDecrypt.setup() != SDK_SUCCESS)
        return SDK_FAILURE;
    if(clAESEncryptDecrypt.run() != SDK_SUCCESS)
        return SDK_FAILURE;
    if(clAESEncryptDecrypt.verifyResults() != SDK_SUCCESS)
        return SDK_FAILURE;
    if(clAESEncryptDecrypt.cleanup() != SDK_SUCCESS)
        return SDK_FAILURE;
    clAESEncryptDecrypt.printStats();
    return SDK_SUCCESS;
}
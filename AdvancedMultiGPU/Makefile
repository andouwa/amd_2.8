DEPTH = ../../../../..

include $(DEPTH)/make/openclsdkdefs.mk 

####
#
#  Targets
#
####

OPENCL			= 1
SAMPLE_EXE		= 1
EXE_TARGET 		= AdvancedMultiGPU
EXE_TARGET_INSTALL   	= AdvancedMultiGPU

####
#
#  C/CPP files
#
####

FILES 	= AESEncrypt device
CLFILES	= AdvancedMultiGPU_Kernels.cl

include $(DEPTH)/make/openclsdkrules.mk 


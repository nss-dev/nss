#! gmake
#
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the Netscape security libraries.
#
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 1994-2000
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Stephen Fung <fungstep@hotmail.com> and
#   Douglas Stebila <douglas@stebila.ca>, Sun Microsystems Laboratories
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

#######################################################################
# (1) Include initial platform-independent assignments (MANDATORY).   #
#######################################################################

include manifest.mn

#######################################################################
# (2) Include "global" configuration information. (OPTIONAL)          #
#######################################################################

include $(CORE_DEPTH)/coreconf/config.mk

#######################################################################
# (3) Include "component" configuration information. (OPTIONAL)       #
#######################################################################

GCC_OPTIMIZER = -O3  -mno-omit-leaf-frame-pointer -fno-omit-frame-pointer

## We have to define this variable now so the right sources are pulled
##  from manifest.mn.
## TFM works only with gcc, and we have only tested it on AMD64 so far.
#ifeq ($(CPU_ARCH),x86_64)
#ifdef NS_USE_GCC
#    NSS_USE_TFM = 1
#    CSRCS += $(TFM_SRCS)
#    OPTIMIZER += $(GCC_OPTIMIZER)
#endif
#endif

#######################################################################
# (4) Include "local" platform-dependent assignments (OPTIONAL).      #
#######################################################################

-include config.mk

ifdef NSS_USE_TFM
ANSI=
DEFINES += -DNSS_USE_TFM
endif

ifdef USE_64
    DEFINES += -DNSS_USE_64
endif

ifdef USE_ABI32_FPU
    DEFINES += -DNSS_USE_ABI32_FPU
endif

# des.c wants _X86_ defined for intel CPUs.  
# coreconf does this for windows, but not for Linux, FreeBSD, etc.
ifeq ($(CPU_ARCH),x86)
ifneq (,$(filter-out WIN%,$(OS_TARGET)))
	OS_REL_CFLAGS += -D_X86_
endif
endif

ifeq ($(OS_TARGET),OSF1)
    DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_NO_MP_WORD
    MPI_SRCS += mpvalpha.c
endif

ifeq (,$(filter-out WINNT WIN95,$(OS_TARGET)))  #omits WIN16 and WINCE
ifdef NS_USE_GCC
# Ideally, we want to use assembler
#     ASFILES  = mpi_x86.s
#     DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE \
#                -DMP_ASSEMBLY_DIV_2DX1D
# but we haven't figured out how to make it work, so we are not
# using assembler right now.
    ASFILES  =
    DEFINES += -DMP_NO_MP_WORD -DMP_USE_UINT_DIGIT
else
    ASFILES  = mpi_x86.asm
    DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE 
    DEFINES += -DMP_ASSEMBLY_DIV_2DX1D -DMP_USE_UINT_DIGIT -DMP_NO_MP_WORD
    ifdef BUILD_OPT
	OPTIMIZER += -Ox  # maximum optimization for freebl
    endif
endif
endif

ifeq ($(OS_TARGET),WINCE)
    DEFINES += -DMP_ARGCHK=0	# no assert in WinCE
    DEFINES += -DSHA_NO_LONG_LONG # avoid 64-bit arithmetic in SHA512
endif

ifdef XP_OS2_VACPP
    ASFILES  = mpi_x86.asm
    DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE 
    DEFINES += -DMP_ASSEMBLY_DIV_2DX1D -DMP_USE_UINT_DIGIT -DMP_NO_MP_WORD
endif

ifeq ($(OS_TARGET),IRIX)
ifeq ($(USE_N32),1)
    ASFILES  = mpi_mips.s
    ifeq ($(NS_USE_GCC),1)
	ASFLAGS = -Wp,-P -Wp,-traditional -O -mips3
    else
	ASFLAGS = -O -OPT:Olimit=4000 -dollar -fullwarn -xansi -n32 -mips3 
    endif
    DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE
    DEFINES += -DMP_USE_UINT_DIGIT
endif
endif

ifeq ($(OS_TARGET),Linux)
ifeq ($(CPU_ARCH),x86_64)
    ASFILES  = arcfour-amd64-gas.s mpi_amd64_gas.s
    ASFLAGS += -march=opteron -m64 -fPIC
    DEFINES += -DNSS_BEVAND_ARCFOUR -DMPI_AMD64 -DMP_ASSEMBLY_MULTIPLY
    DEFINES += -DNSS_USE_COMBA
    MPI_SRCS += mpi_amd64.c mp_comba.c
# When compiling with -ansi, gcc chokes on some of the asm
# statements in mp_comba.c.  Clear the flag for freebl.
    ANSI =
    ifdef BUILD_OPT
	OPTIMIZER = $(GCC_OPTIMIZER)
    endif
endif
ifeq ($(CPU_ARCH),x86)
ifndef NSS_USE_TFM
    ASFILES  = mpi_x86.s
    DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE 
    DEFINES += -DMP_ASSEMBLY_DIV_2DX1D
else
    OPTIMIZER = -O3 -fomit-frame-pointer
    DEFINES += -DTFM_SSE2
endif
    USE_FP_CODE = 1
    ifdef BUILD_OPT
	OPTIMIZER = $(GCC_OPTIMIZER)
    endif
endif
ifdef NSS_ENABLE_ECC
    ifdef USE_FP_CODE
	#enable floating point ECC code	
	DEFINES  += -DECL_USE_FP
	ECL_SRCS += ecp_fp160.c ecp_fp192.c ecp_fp224.c ecp_fp.c
	ECL_HDRS += ecp_fp.h
    endif
endif # NSS_ENABLE_ECC
endif # Linux

ifeq ($(OS_TARGET),AIX)
    DEFINES += -DMP_USE_UINT_DIGIT
    ifndef USE_64
	DEFINES += -DMP_NO_DIV_WORD -DMP_NO_ADD_WORD -DMP_NO_SUB_WORD
    endif
endif # AIX

ifeq ($(OS_TARGET), HP-UX)
ifneq ($(OS_TEST), ia64)
MKSHLIB += +k +vshlibunsats -u FREEBL_GetVector +e FREEBL_GetVector
ifndef FREEBL_EXTENDED_BUILD
ifdef USE_ABI32_INT32
# build for DA1.1 (HP PA 1.1) pure 32 bit model
    DEFINES  += -DMP_USE_UINT_DIGIT -DMP_NO_MP_WORD
    DEFINES += -DSHA_NO_LONG_LONG # avoid 64-bit arithmetic in SHA512
else
ifdef USE_64
# this builds for DA2.0W (HP PA 2.0 Wide), the LP64 ABI, using 32-bit digits 
    MPI_SRCS += mpi_hp.c 
    ASFILES  += hpma512.s hppa20.s 
    DEFINES  += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE
else
# this builds for DA2.0 (HP PA 2.0 Narrow) ABI32_FPU model 
# (the 32-bit ABI with 64-bit registers) using 32-bit digits
    MPI_SRCS += mpi_hp.c 
    ASFILES  += hpma512.s hppa20.s 
    DEFINES  += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE
endif
endif
endif
endif
endif

# Note: -xarch=v8 or v9 is now done in coreconf
ifeq ($(OS_TARGET),SunOS)

# The -R '$ORIGIN' linker option instructs this library to search for its
# dependencies in the same directory where it resides.
MKSHLIB += -R '$$ORIGIN'

ifeq ($(CPU_ARCH),sparc)
    ifndef NS_USE_GCC
	ifdef USE_ABI32_FPU
	    OS_CFLAGS += -xchip=ultra2
	endif # USE_ABI32_FPU
    endif # NS_USE_GCC
    SYSV_SPARC=1
    SOLARIS_AS = /usr/ccs/bin/as
    ifdef NS_USE_GCC
	ifdef GCC_USE_GNU_LD
	    MKSHLIB += -Wl,-Bsymbolic,-z,defs,-z,now,-z,text,--version-script,mapfile.Solaris
	else
	    MKSHLIB += -Wl,-B,symbolic,-z,defs,-z,now,-z,text,-M,mapfile.Solaris
	endif # GCC_USE_GNU_LD
    else
	MKSHLIB += -B symbolic -z defs -z now -z text -M mapfile.Solaris
    endif # NS_USE_GCC
    ifdef USE_ABI32_INT32
	# this builds for Sparc v8 pure 32-bit architecture
	DEFINES += -DMP_ASSEMBLY_MULTIPLY
	ASFILES  = mpv_sparcv8x.s
	DEFINES += -DMP_NO_MP_WORD -DMP_USE_UINT_DIGIT 
	DEFINES += -DSHA_NO_LONG_LONG # avoid 64-bit arithmetic in SHA512
    endif
    ifdef USE_ABI32_INT64
	# this builds for Sparc v8+a ABI32_FPU architecture, 64-bit registers, 
	# 32-bit ABI, it uses 64-bit words, integer arithmetic, no FPU
#	DEFINES  += -DMP_USE_UINT_DIGIT 
	DEFINES  += -DMP_NO_MP_WORD 
	SOLARIS_AS_FLAGS = -xarch=v8plusa -K PIC
    endif
    ifdef USE_ABI32_FPU
	# this builds for Sparc v8+a ABI32_FPU architecture, 64-bit registers, 
	# 32-bit ABI, it uses FPU code, and 32-bit word size
	MPI_SRCS += mpi_sparc.c
	ASFILES  = mpv_sparcv8.s montmulfv8.s
	DEFINES  += -DMP_ASSEMBLY_MULTIPLY -DMP_USING_MONT_MULF 
	DEFINES  += -DMP_NO_MP_WORD  -DMP_USE_UINT_DIGIT
	SOLARIS_AS_FLAGS = -xarch=v8plusa -K PIC
    endif
    ifdef USE_ABI64_INT
	# this builds for Sparc v9a pure 64-bit architecture
#	DEFINES  += -DMP_USE_UINT_DIGIT 
	DEFINES  += -DMP_NO_MP_WORD 
	SOLARIS_FLAGS  = -fast -xO5 -xrestrict=%all -xchip=ultra -xarch=v9a
	SOLARIS_FLAGS += -KPIC -mt
	SOLARIS_AS_FLAGS = -xarch=v9a -K PIC
    endif
    ifdef USE_ABI64_FPU
	# this builds for Sparc v9a pure 64-bit architecture
	# It uses floating point, and 32-bit word size
	MPI_SRCS += mpi_sparc.c
	ASFILES   = mpv_sparcv9.s montmulfv9.s
	DEFINES  += -DMP_ASSEMBLY_MULTIPLY -DMP_USING_MONT_MULF
	DEFINES  += -DMP_USE_UINT_DIGIT 
	SOLARIS_FLAGS  = -fast -xO5 -xrestrict=%all -xchip=ultra -xarch=v9a
	SOLARIS_FLAGS += -KPIC -mt
	SOLARIS_AS_FLAGS = -xarch=v9a -K PIC
    endif

    ifdef NSS_ENABLE_ECC
	DEFINES  += -DECL_USE_FP
	ECL_SRCS += ecp_fp160.c ecp_fp192.c ecp_fp224.c ecp_fp.c
	ECL_HDRS += ecp_fp.h
    endif # NSS_ENABLE_ECC
else
    # Solaris for non-sparc family CPUs
    ifdef NS_USE_GCC
	LD = gcc
	AS = gcc
	ASFLAGS =
	ifdef BUILD_OPT
	    OPTIMIZER = $(GCC_OPTIMIZER)
	endif
    endif
    ifeq ($(USE_64),1)
	# Solaris for AMD64
	ifdef NS_USE_GCC
	    ASFILES  = arcfour-amd64-gas.s mpi_amd64_gas.s
	    ASFLAGS += -march=opteron -m64 -fPIC
	    MPI_SRCS += mp_comba.c
	else
	    ASFILES  = arcfour-amd64-sun.s mpi_amd64_sun.s
	    ASFILES += mp_comba_amd64_sun.s
	    ASFLAGS += -xarch=generic64 -K PIC
	endif
	DEFINES += -DNSS_BEVAND_ARCFOUR -DMPI_AMD64 -DMP_ASSEMBLY_MULTIPLY
	DEFINES += -DNSS_USE_COMBA
	MPI_SRCS += mpi_amd64.c
    else
	# Solaris x86
	DEFINES += -D_X86_
	DEFINES += -DMP_USE_UINT_DIGIT
	DEFINES += -DMP_ASSEMBLY_MULTIPLY -DMP_ASSEMBLY_SQUARE 
	DEFINES += -DMP_ASSEMBLY_DIV_2DX1D
	ASFILES  = mpi_i86pc.s
    endif
endif # Solaris for non-sparc family CPUs
endif # target == SunOS

$(OBJDIR)/sysrand$(OBJ_SUFFIX): sysrand.c unix_rand.c win_rand.c mac_rand.c os2_rand.c

#######################################################################
# (5) Execute "global" rules. (OPTIONAL)                              #
#######################################################################

include $(CORE_DEPTH)/coreconf/rules.mk

#######################################################################
# (6) Execute "component" rules. (OPTIONAL)                           #
#######################################################################



#######################################################################
# (7) Execute "local" rules. (OPTIONAL).                              #
#######################################################################

export:: private_export

rijndael_tables:
	$(CC) -o $(OBJDIR)/make_rijndael_tab rijndael_tables.c \
	         $(DEFINES) $(INCLUDES) $(OBJDIR)/libfreebl.a
	$(OBJDIR)/make_rijndael_tab

ifdef FREEBL_RECURSIVE_BUILD
vpath %.h $(FREEBL_PARENT)/ecl $(FREEBL_PARENT)/mpi $(FREEBL_PARENT)
vpath %.c $(FREEBL_PARENT)/ecl $(FREEBL_PARENT)/mpi $(FREEBL_PARENT)
vpath %.S $(FREEBL_PARENT)/ecl $(FREEBL_PARENT)/mpi $(FREEBL_PARENT)
vpath %.s $(FREEBL_PARENT)/ecl $(FREEBL_PARENT)/mpi $(FREEBL_PARENT)
vpath %.asm $(FREEBL_PARENT)/ecl $(FREEBL_PARENT)/mpi $(FREEBL_PARENT)
INCLUDES += -I$(FREEBL_PARENT) -I$(FREEBL_PARENT)/mpi -I$(FREEBL_PARENT)/ecl
else
vpath %.h mpi ecl tfm
vpath %.c mpi ecl tfm
vpath %.S mpi ecl
vpath %.s mpi ecl
vpath %.asm mpi ecl
INCLUDES += -Impi -Iecl -Itfm
endif


DEFINES += -DMP_API_COMPATIBLE

# These defines force a rebuild when headers are newer than source

MPI_USERS = dh.c pqg.c dsa.c rsa.c rsa_keygen.c ec.c

MPI_OBJS = $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(MPI_SRCS:.c=$(OBJ_SUFFIX)))
MPI_OBJS += $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(MPI_USERS:.c=$(OBJ_SUFFIX)))

$(MPI_OBJS): $(MPI_HDRS)

ECL_USERS = ec.c

ECL_OBJS = $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(ECL_SRCS:.c=$(OBJ_SUFFIX)) $(ECL_ASM_SRCS:$(ASM_SUFFIX)=$(OBJ_SUFFIX)))
ECL_OBJS += $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(ECL_USERS:.c=$(OBJ_SUFFIX)))

$(ECL_OBJS): $(ECL_HDRS)

ifdef NSS_USE_TFM
TFM_USERS = rsa.c rsa_keygen.c

TFM_OBJS = $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(TFM_SRCS:.c=$(OBJ_SUFFIX)))
TFM_OBJS += $(addprefix $(OBJDIR)/$(PROG_PREFIX), $(TFM_USERS:.c=$(OBJ_SUFFIX)))

$(TFM_OBJS): $(TFM_HDRS)
endif


$(OBJDIR)/$(PROG_PREFIX)mpprime$(OBJ_SUFFIX): primes.c

$(OBJDIR)/ldvector$(OBJ_SUFFIX) $(OBJDIR)/loader$(OBJ_SUFFIX) : loader.h

ifeq ($(SYSV_SPARC),1)

$(OBJDIR)/mpv_sparcv8.o $(OBJDIR)/montmulfv8.o : $(OBJDIR)/%.o : %.s 
	@$(MAKE_OBJDIR)
	$(SOLARIS_AS) -o $@ $(SOLARIS_AS_FLAGS) $<

$(OBJDIR)/mpv_sparcv9.o $(OBJDIR)/montmulfv9.o : $(OBJDIR)/%.o : %.s
	@$(MAKE_OBJDIR)
	$(SOLARIS_AS) -o $@ $(SOLARIS_AS_FLAGS) $<

$(OBJDIR)/mpmontg.o: mpmontg.c montmulf.h

endif

ifdef FREEBL_EXTENDED_BUILD

CDDIR := $(shell pwd)
FILES2LN = \
 $(wildcard *.tab) \
 $(wildcard mapfile.*) \
 Makefile manifest.mn config.mk 

ifndef USE_64 
######################## ABI32_FPU stuff #########################
ABI32_FPU_DIR = $(OBJDIR)/$(OS_TARGET)_ABI32_FPU
ABI32_FPU_FILES = $(addprefix $(ABI32_FPU_DIR)/, $(FILES2LN))
ALL_TRASH += $(ABI32_FPU_DIR) 

$(ABI32_FPU_DIR):
	-mkdir $(ABI32_FPU_DIR)
	-ln -s $(CDDIR)/mpi $(ABI32_FPU_DIR)

$(ABI32_FPU_FILES) : $(ABI32_FPU_DIR)/% : % 
	ln -s $(CDDIR)/$* $(ABI32_FPU_DIR)

libs:: $(ABI32_FPU_DIR) $(ABI32_FPU_FILES)
	cd $(ABI32_FPU_DIR) && $(MAKE) FREEBL_RECURSIVE_BUILD=1 USE_ABI32_FPU=1 \
 FREEBL_PARENT=$(CDDIR) CORE_DEPTH=$(CDDIR)/$(CORE_DEPTH) libs

######################## ABI32_INT32 stuff #########################
ABI32_INT32_DIR = $(OBJDIR)/$(OS_TARGET)_ABI32_INT32
ABI32_INT32_FILES = $(addprefix $(ABI32_INT32_DIR)/, $(FILES2LN))
ALL_TRASH += $(ABI32_INT32_DIR) 

$(ABI32_INT32_DIR):
	-mkdir $(ABI32_INT32_DIR)
	-ln -s $(CDDIR)/mpi $(ABI32_INT32_DIR)

$(ABI32_INT32_FILES) : $(ABI32_INT32_DIR)/% : % 
	ln -s $(CDDIR)/$* $(ABI32_INT32_DIR)

libs:: $(ABI32_INT32_DIR) $(ABI32_INT32_FILES)
	cd $(ABI32_INT32_DIR) && $(MAKE) FREEBL_RECURSIVE_BUILD=1 USE_ABI32_INT32=1 \
 FREEBL_PARENT=$(CDDIR) CORE_DEPTH=$(CDDIR)/$(CORE_DEPTH) libs

######################## ABI32_INT64 stuff #########################
ifeq ($(OS_TARGET),SunOS)
ifeq ($(CPU_ARCH),sparc)

ABI32_INT64_DIR = $(OBJDIR)/$(OS_TARGET)_ABI32_INT64
ABI32_INT64_FILES = $(addprefix $(ABI32_INT64_DIR)/, $(FILES2LN))
ALL_TRASH += $(ABI32_INT64_DIR) 

$(ABI32_INT64_DIR):
	-mkdir $(ABI32_INT64_DIR)
	-ln -s $(CDDIR)/mpi $(ABI32_INT64_DIR)

$(ABI32_INT64_FILES) : $(ABI32_INT64_DIR)/% : % 
	ln -s $(CDDIR)/$* $(ABI32_INT64_DIR)

libs:: $(ABI32_INT64_DIR) $(ABI32_INT64_FILES)
	cd $(ABI32_INT64_DIR) && $(MAKE) FREEBL_RECURSIVE_BUILD=1 USE_ABI32_INT64=1 \
 FREEBL_PARENT=$(CDDIR) CORE_DEPTH=$(CDDIR)/$(CORE_DEPTH) libs
endif
endif
######################## END of 32-bit stuff #########################

else # above is 32-bit builds, below is 64-bit builds

######################## ABI64_FPU stuff #########################
ifeq ($(OS_TARGET),SunOS)
ifeq ($(CPU_ARCH),sparc)
ABI64_FPU_DIR = $(OBJDIR)/$(OS_TARGET)_ABI64_FPU
ABI64_FPU_FILES = $(addprefix $(ABI64_FPU_DIR)/, $(FILES2LN))
ALL_TRASH += $(ABI64_FPU_DIR) 

$(ABI64_FPU_DIR):
	-mkdir $(ABI64_FPU_DIR)
	-ln -s $(CDDIR)/mpi $(ABI64_FPU_DIR)

$(ABI64_FPU_FILES) : $(ABI64_FPU_DIR)/% : % 
	ln -s $(CDDIR)/$* $(ABI64_FPU_DIR)

libs:: $(ABI64_FPU_DIR) $(ABI64_FPU_FILES)
	cd $(ABI64_FPU_DIR) && $(MAKE) FREEBL_RECURSIVE_BUILD=1 USE_ABI64_FPU=1 \
 FREEBL_PARENT=$(CDDIR) CORE_DEPTH=$(CDDIR)/$(CORE_DEPTH) libs
endif
endif

######################## ABI64_INT stuff #########################
ifeq ($(OS_TARGET),SunOS)
ifeq ($(CPU_ARCH),sparc)
ABI64_INT_DIR = $(OBJDIR)/$(OS_TARGET)_ABI64_INT
ABI64_INT_FILES = $(addprefix $(ABI64_INT_DIR)/, $(FILES2LN))
ALL_TRASH += $(ABI64_INT_DIR) 

$(ABI64_INT_DIR):
	-mkdir $(ABI64_INT_DIR)
	-ln -s $(CDDIR)/mpi $(ABI64_INT_DIR)

$(ABI64_INT_FILES) : $(ABI64_INT_DIR)/% : % 
	ln -s $(CDDIR)/$* $(ABI64_INT_DIR)

libs:: $(ABI64_INT_DIR) $(ABI64_INT_FILES)
	cd $(ABI64_INT_DIR) && $(MAKE) FREEBL_RECURSIVE_BUILD=1 USE_ABI64_INT=1 \
 FREEBL_PARENT=$(CDDIR) CORE_DEPTH=$(CDDIR)/$(CORE_DEPTH) libs
endif
endif
######################## common stuff #########################

endif # 32b or 64b recursive builds


release_md:: $(libs)

endif  # FREEBL_EXTENDED_BUILD

# Bugzilla Bug 209827: disable optimization to work around what appears
# to be a VACPP optimizer bug.
ifdef XP_OS2_VACPP
$(OBJDIR)/alg2268.obj: alg2268.c
	@$(MAKE_OBJDIR)
	$(CC) -Fo$@ -c $(filter-out /O+, $(CFLAGS)) $(call abspath,$<)
endif

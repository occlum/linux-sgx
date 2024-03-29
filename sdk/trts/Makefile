#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include ../../buildenv.mk

CPPFLAGS += -I$(COMMON_DIR)/inc          \
            -I$(COMMON_DIR)/inc/internal \
            -I$(COMMON_DIR)/inc/tlibc    \
            -I$(LINUX_SDK_DIR)/tlibcxx/include \
            -I$(LINUX_SDK_DIR)/pthread

CXXFLAGS += $(ENCLAVE_CXXFLAGS) \
            -Werror         \
            -fno-exceptions \
            -fno-rtti

TCXXFLAGS := $(patsubst -fstack-protector%,-fno-stack-protector,$(CXXFLAGS))

OBJS1 := init_enclave.o  \
        trts.o           \
        trts_ecall.o     \
        trts_ocall.o     \
        ema_init.o     \
        trts_util.o      \
        trts_veh.o       \
        trts_xsave.o     \
        init_optimized_lib.o \
        trts_version.o \
        trts_interrupt.o  \
        trts_add_trim.o

OBJS2 := trts_nsp.o

OBJS3 := ema_rt.o

OBJS := $(OBJS1) $(OBJS2) $(OBJ3)

all: $(OBJS) elf_parser

$(OBJS1): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) -fPIC $< -o $@
	objcopy $@ --set-section-flags .niprod='alloc','readonly'

$(OBJS2): %.o: %.cpp
	$(CXX) -c $(TCXXFLAGS) $(CPPFLAGS) -fPIC $< -o $@

$(OBJS3): %.o: %.c
	$(CC) -c $(TCFLAGS) $(CFLAGS) -fPIC $< -o $@

.PHONY: elf_parser
elf_parser: $(OBJS)
	$(MAKE) -C linux

.PHONY: clean
clean:
	@$(RM) $(OBJS) *.bak *~
	$(MAKE) -C linux clean

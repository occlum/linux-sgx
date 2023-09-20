/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_tprotected_fs.h"
#include "sgx_tprotected_fs_t.h"
#include "protected_fs_file.h"

#include <errno.h>

static SGX_FILE* sgx_fopen_internal(const char* filename, const char* mode, const sgx_key_128bit_t *auto_key, const sgx_key_128bit_t *kdk_key, const uint16_t key_policy, const uint8_t operate_mode, const uint8_t encrypt_flags, const uint64_t cache_size)
{
	protected_fs_file* file = NULL;
	uint32_t cache_page = 0;

	if (filename == NULL || mode == NULL ||
		cache_size < DEFAULT_CACHE_SIZE || cache_size % SE_PAGE_SIZE != 0 ||
		(cache_size / SE_PAGE_SIZE) > UINT_MAX)
	{
		errno = EINVAL;
		return NULL;
	}

	if ((encrypt_flags == USE_AUTO_KEY) && (operate_mode == OPEN_FILE || operate_mode == IMPORT_KEY))
	{
		if ((key_policy & ~(SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER | SGX_KEYPOLICY_CONFIGID | SGX_KEYPOLICY_ISVFAMILYID | SGX_KEYPOLICY_ISVEXTPRODID | SGX_KEYPOLICY_NOISVPRODID)) ||
			(key_policy & (SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)) == 0)
		{
			errno = EINVAL;
			return NULL;
		}
	}

	cache_page = (uint32_t) (cache_size / SE_PAGE_SIZE);

	try {
		file = new protected_fs_file(filename, mode, auto_key, kdk_key, key_policy, operate_mode, encrypt_flags, cache_page);
	}
	catch (std::bad_alloc& e) {
		(void)e; // remove warning
		errno = ENOMEM;
		return NULL;
	}

	if (file->get_error() != SGX_FILE_STATUS_OK)
	{
		errno = file->get_error();
		delete file;
		file = NULL;
	}

	return (SGX_FILE*)file;
}


SGX_FILE* sgx_fopen_auto_key(const char* filename, const char* mode)
{
	return sgx_fopen_internal(filename, mode, NULL, NULL, SGX_KEYPOLICY_MRSIGNER, OPEN_FILE, USE_AUTO_KEY, DEFAULT_CACHE_SIZE);
}

SGX_FILE* sgx_fopen_integrity_only(const char* filename, const char* mode)
{
	return sgx_fopen_internal(filename, mode, NULL, NULL, 0, OPEN_FILE, USE_INTEGRITY_ONLY, DEFAULT_CACHE_SIZE);
}

SGX_FILE* sgx_fopen(const char* filename, const char* mode, const sgx_key_128bit_t *key)
{
	return sgx_fopen_internal(filename, mode, NULL, key, 0, OPEN_FILE, USE_USER_KDK_KEY, DEFAULT_CACHE_SIZE);
}

SGX_FILE* SGXAPI sgx_fopen_ex(const char* filename, const char* mode, const sgx_key_128bit_t *key, const uint16_t key_policy, const uint64_t cache_size)
{
	uint16_t auto_key_policy = 0;
	uint8_t encrypt_flags = key ? USE_USER_KDK_KEY: USE_AUTO_KEY;
	uint64_t file_cache_size = cache_size ? cache_size : DEFAULT_CACHE_SIZE;

	if (encrypt_flags == USE_USER_KDK_KEY && key_policy != 0)
	{
		errno = EINVAL;
		return NULL;
	}
	if (encrypt_flags == USE_AUTO_KEY)
	{
		auto_key_policy = key_policy ? key_policy : SGX_KEYPOLICY_MRSIGNER;
	}
	return sgx_fopen_internal(filename, mode, NULL, key, auto_key_policy, OPEN_FILE, encrypt_flags, file_cache_size);
}


size_t sgx_fwrite(const void* ptr, size_t size, size_t count, SGX_FILE* stream)
{
	if (ptr == NULL || stream == NULL || size == 0 || count == 0)
		return 0;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->write(ptr, size, count);
}


size_t sgx_fread(void* ptr, size_t size, size_t count, SGX_FILE* stream)
{
	if (ptr == NULL || stream == NULL || size == 0 || count == 0)
		return 0;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->read(ptr, size, count);
}


int64_t sgx_ftell(SGX_FILE* stream)
{
	if (stream == NULL)
		return -1;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->tell();
}


int32_t sgx_fseek(SGX_FILE* stream, int64_t offset, int origin)
{
	if (stream == NULL)
		return -1;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->seek(offset, origin);
}


int32_t sgx_fflush(SGX_FILE* stream)
{
	if (stream == NULL)
		return EOPNOTSUPP; // TBD - currently we don't support NULL as fflush input parameter

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->flush(/*false*/) == true ? 0 : EOF;
}


int32_t sgx_ferror(SGX_FILE* stream)
{
	if (stream == NULL)
		return -1;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->get_error();
}


int32_t sgx_feof(SGX_FILE* stream)
{
	if (stream == NULL)
		return -1;

	protected_fs_file* file = (protected_fs_file*)stream;

	return ((file->get_eof() == true) ? 1 : 0);
}


void sgx_clearerr(SGX_FILE* stream)
{
	if (stream == NULL)
		return;

	protected_fs_file* file = (protected_fs_file*)stream;

	file->clear_error();
}


static int32_t sgx_fclose_internal(SGX_FILE* stream, sgx_key_128bit_t *key, bool import)
{
	int32_t retval = 0;

	if (stream == NULL)
		return EOF;

	protected_fs_file* file = (protected_fs_file*)stream;

	if (file->pre_close(key, import) == false)
		retval = 1;

	delete file;

	return retval;
}


int32_t sgx_fclose(SGX_FILE* stream)
{
	return sgx_fclose_internal(stream, NULL, false);
}


int32_t sgx_remove(const char* filename)
{
	return protected_fs_file::remove(filename);
}


int32_t sgx_fexport_auto_key(const char* filename, sgx_key_128bit_t *key)
{
	SGX_FILE* stream = sgx_fopen_internal(filename, "r", NULL, NULL, 0, EXPORT_KEY, USE_AUTO_KEY, DEFAULT_CACHE_SIZE);
	if (stream == NULL)
		return 1;

	return sgx_fclose_internal(stream, key, false);
}


int32_t sgx_fimport_auto_key(const char* filename, const sgx_key_128bit_t *key, const uint16_t key_policy)
{
	uint16_t auto_key_policy = key_policy ? key_policy : SGX_KEYPOLICY_MRSIGNER;
	SGX_FILE* stream = sgx_fopen_internal(filename, "r+", key, NULL, auto_key_policy, IMPORT_KEY, USE_AUTO_KEY, DEFAULT_CACHE_SIZE);
	if (stream == NULL)
		return 1;

	return sgx_fclose_internal(stream, NULL, true);
}


int32_t sgx_fclear_cache(SGX_FILE* stream)
{
	if (stream == NULL)
		return 1;

	protected_fs_file* file = (protected_fs_file*)stream;

	return file->clear_cache();
}


int32_t SGXAPI sgx_fget_mac(SGX_FILE* stream, sgx_aes_gcm_128bit_tag_t* mac)
{
	if (stream == NULL)
		return 1;

	protected_fs_file* file = (protected_fs_file*)stream;
	if (file->flush() == false)
		return 1;

	return file->get_root_mac(mac);
}

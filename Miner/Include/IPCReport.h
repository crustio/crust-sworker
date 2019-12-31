/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#ifndef IPCREPORT_H_
#define IPCREPORT_H_

#define IPC_MK_ERROR(x)     (0x00000000|(x))

typedef enum _ipc_status_t {
    IPC_SUCCESS                 = IPC_MK_ERROR(0x00),
    INVALID_PARAMETER           = IPC_MK_ERROR(0xE1),
    VALID_SESSION               = IPC_MK_ERROR(0xE2),
    INVALID_SESSION             = IPC_MK_ERROR(0xE3),
    ATTESTATION_ERROR           = IPC_MK_ERROR(0xE4),
    ATTESTATION_SE_ERROR        = IPC_MK_ERROR(0xE5),
    IPP_ERROR                   = IPC_MK_ERROR(0xE6),
    NO_AVAILABLE_SESSION_ERROR  = IPC_MK_ERROR(0xE7),
    MALLOC_ERROR                = IPC_MK_ERROR(0xE8),
    ERROR_TAG_MISMATCH          = IPC_MK_ERROR(0xE9),
    OUT_BUFFER_LENGTH_ERROR     = IPC_MK_ERROR(0xEA),
    INVALID_REQUEST_TYPE_ERROR  = IPC_MK_ERROR(0xEB),
    INVALID_PARAMETER_ERROR     = IPC_MK_ERROR(0xEC),
    ENCLAVE_TRUST_ERROR         = IPC_MK_ERROR(0xED),
    ENCRYPT_DECRYPT_ERROR       = IPC_MK_ERROR(0xEE),
    DUPLICATE_SESSION           = IPC_MK_ERROR(0xEF),
    ATTESTATION_BADREQUEST      = IPC_MK_ERROR(0xF1),
    IPC_TRANSFER_ERROR          = IPC_MK_ERROR(0xF2),
    IPC_SENDMSG_ERROR           = IPC_MK_ERROR(0xF3),
    IPC_RECVMSG_ERROR           = IPC_MK_ERROR(0xF4),
    IPC_CREATE_THREAD_ERR       = IPC_MK_ERROR(0xF5),
    IPC_SGX_ERROR               = IPC_MK_ERROR(0xF6),
    IPC_BADSESSIONTYPE          = IPC_MK_ERROR(0xF7),
} ipc_status_t;

#endif

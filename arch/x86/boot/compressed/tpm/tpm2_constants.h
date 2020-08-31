// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * The definitions in this header are extracted and/or dervied from the
 * Trusted Computing Group's TPM 2.0 Library Specification Parts 1&2.
 *
 */

#ifndef _TPM2_CONSTANTS_H
#define _TPM2_CONSTANTS_H

/* Table 9  Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */
#define TPM_ALG_ERROR                (u16)(0x0000)
#define TPM_ALG_RSA                  (u16)(0x0001)
#define TPM_ALG_SHA                  (u16)(0x0004)
#define TPM_ALG_SHA1                 (u16)(0x0004)
#define TPM_ALG_HMAC                 (u16)(0x0005)
#define TPM_ALG_AES                  (u16)(0x0006)
#define TPM_ALG_MGF1                 (u16)(0x0007)
#define TPM_ALG_KEYEDHASH            (u16)(0x0008)
#define TPM_ALG_XOR                  (u16)(0x000A)
#define TPM_ALG_SHA256               (u16)(0x000B)
#define TPM_ALG_SHA384               (u16)(0x000C)
#define TPM_ALG_SHA512               (u16)(0x000D)
#define TPM_ALG_NULL                 (u16)(0x0010)
#define TPM_ALG_SM3_256              (u16)(0x0012)
#define TPM_ALG_SM4                  (u16)(0x0013)
#define TPM_ALG_RSASSA               (u16)(0x0014)
#define TPM_ALG_RSAES                (u16)(0x0015)
#define TPM_ALG_RSAPSS               (u16)(0x0016)
#define TPM_ALG_OAEP                 (u16)(0x0017)
#define TPM_ALG_ECDSA                (u16)(0x0018)
#define TPM_ALG_ECDH                 (u16)(0x0019)
#define TPM_ALG_ECDAA                (u16)(0x001A)
#define TPM_ALG_SM2                  (u16)(0x001B)
#define TPM_ALG_ECSCHNORR            (u16)(0x001C)
#define TPM_ALG_ECMQV                (u16)(0x001D)
#define TPM_ALG_KDF1_SP800_56A       (u16)(0x0020)
#define TPM_ALG_KDF2                 (u16)(0x0021)
#define TPM_ALG_KDF1_SP800_108       (u16)(0x0022)
#define TPM_ALG_ECC                  (u16)(0x0023)
#define TPM_ALG_SYMCIPHER            (u16)(0x0025)
#define TPM_ALG_CAMELLIA             (u16)(0x0026)
#define TPM_ALG_CTR                  (u16)(0x0040)
#define TPM_ALG_OFB                  (u16)(0x0041)
#define TPM_ALG_CBC                  (u16)(0x0042)
#define TPM_ALG_CFB                  (u16)(0x0043)
#define TPM_ALG_ECB                  (u16)(0x0044)
#define TPM_ALG_FIRST                (u16)(0x0001)
#define TPM_ALG_LAST                 (u16)(0x0044)

/* Table 12  Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */
#define TPM_CC_PCR_EXTEND (u32)(0x00000182)

/* Table 19  Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */
#define TPM_ST_NO_SESSIONS (u16)(0x8001)
#define TPM_ST_SESSIONS (u16)(0x8002)

/* Table 28  Definition of (TPM_HANDLE) TPM_RH Constants <S> */
#define TPM_RS_PW (u32)(0x40000009)

#endif

/**
 * \file XTEA-Cipher.h
 * \brief XTEA cipher library, size-optimized (C++ class version).
 *
 * \copyright SPDX-FileCopyrightText: Copyright 2020-2021 Michal Protasowicki
 *
 * \license SPDX-License-Identifier: MIT
 *
 */

#pragma once

#include "Arduino.h"
#include "xtea.h"

/**
 *  \brief XteaCipher class.
 */
class XteaCipher
{
    public:
        XteaCipher();
        virtual ~XteaCipher();

        void    begin          (void);
        void    begin          (const uint_fast8_t rounds);
        void    begin          (const uint_fast8_t rounds, const uint_fast8_t macRounds);

        boolean ecbEncrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                uint8_t data[],
                                const uint32_t length);
        boolean ecbDecrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                uint8_t data[],
                                const uint32_t length);
        void    cfbEncrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                const uint8_t iv[XTEA_IV_SIZE],
                                uint8_t data[],
                                const uint32_t length);
        void    cfbDecrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                const uint8_t iv[XTEA_IV_SIZE],
                                uint8_t data[],
                                const uint32_t length);
        void    ofbEncrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                const uint8_t iv[XTEA_IV_SIZE],
                                uint8_t data[],
                                const uint32_t length);
        void    ofbDecrypt     (const uint8_t key[XTEA_KEY_SIZE],
                                const uint8_t iv[XTEA_IV_SIZE],
                                uint8_t data[],
                                const uint32_t length);

        void    macCompute     (const uint8_t key[XTEA_KEY_SIZE], uint8_t mac[XTEA_BLOCK_SIZE], const uint8_t data[], const uint32_t length);
        boolean macVerify      (const uint8_t key[XTEA_KEY_SIZE], const uint8_t mac[XTEA_BLOCK_SIZE], const uint8_t data[], const uint32_t length);
        void    macInit        (const uint8_t key[XTEA_KEY_SIZE]);
        void    macUpdate      (const uint8_t data[], const uint32_t length);
        void    macFinish      (void);
        void    macGet         (uint8_t mac[XTEA_BLOCK_SIZE]);
        boolean macCmp         (const uint8_t mac[XTEA_BLOCK_SIZE]);

    private:
        xteaCtx_t       _ctx;
        uint32_t        _startPos;
        uint32_t        _remainingBytes;
        uint_fast8_t    _rounds;
        uint_fast8_t    _macRounds;

        boolean ecbCipher      (const uint8_t key[XTEA_KEY_SIZE], uint8_t data[], const uint32_t length, const xteaOperation_t operation);

        void    feedbackCipher (const uint8_t key[XTEA_KEY_SIZE],
                                const uint8_t iv[XTEA_IV_SIZE],
                                uint8_t data[],
                                const uint32_t length,
                                const xteaOperation_t operation,
                                const boolean isCfb);
};

extern XteaCipher xtea;

/**
 * \file XTEA-Cipher.cpp
 * \brief XTEA cipher library, size-optimized (C++ class version).
 *
 * \copyright SPDX-FileCopyrightText: Copyright 2020-2021 Michal Protasowicki
 *
 * \license SPDX-License-Identifier: MIT
 *
 */

#include "XTEA-Cipher.h"

/**
 * \brief XteaCipher class constructor.
 */
XteaCipher::XteaCipher()
{
    memset(&_ctx, 0x00, sizeof(xteaCtx_t));
}

/**
 * \brief XteaCipher class destructor.
 */   
XteaCipher::~XteaCipher()
{
    memset(&_ctx, 0x00, sizeof(xteaCtx_t));
}

/**
 * \brief   Function that sets number of internal rounds of the cipher,
 *          separately for encryption/decryption operations and calculation of MAC codes.
 *          One of 'begin' function MUST be called at least once before starting other operations.
 *          With its help, you can change number of rounds many times before performing
 *          encryption/decryption operations or MAC code calculation.
 * 
 * \param[in]   rounds      Number of rounds for encryption/decryption.
 * \param[in]   macRounds   Number of rounds for MAC code calculation.
 * 
 * \result nothing
 */
void XteaCipher::begin(const uint_fast8_t rounds, const uint_fast8_t macRounds)
{
    _rounds     = rounds;
    _macRounds  = macRounds;
}

/**
 * \brief   Function that sets number of internal rounds of the cipher,
 *          separately for encryption/decryption operations and calculation of MAC codes.
 *          Number of rounds for MAC code calculation is set to default value.
 *          One of 'begin' function MUST be called at least once before starting other operations.
 *          With its help, you can change number of rounds many times before performing
 *          encryption/decryption operations or MAC code calculation.
 * 
 * \param[in]   rounds      Number of rounds for encryption/decryption.
 * 
 * \result nothing
 */
void XteaCipher::begin(const uint_fast8_t rounds)
{
    begin(rounds, XTEA_MAC_ROUNDS);
}

/**
 * \brief   Function that sets number of internal rounds of the cipher,
 *          separately for encryption/decryption operations and calculation of MAC codes.
 *          Both the number of rounds for encryption/decryption and MAC code calculation are set to default value.
 *          One of 'begin' function MUST be called at least once before starting other operations.
 *          With its help, you can change number of rounds many times before performing
 *          encryption/decryption operations or MAC code calculation.
 * 
 * \result nothing
 */
void XteaCipher::begin(void)
{
    begin(XTEA_ROUNDS, XTEA_MAC_ROUNDS);
}

/**
 * \brief   Function that encrypts data in ECB mode.
 *          In this mode, the amount of data MUST be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
  *
 * \return  Function returns false when length of passed data is NOT a multiple of the data block,
 *          otherwise it returns true. Processed data is returned by the 'data' parameter.
 */
boolean XteaCipher::ecbEncrypt(const uint8_t key[XTEA_KEY_SIZE], uint8_t data[], const uint32_t length)
{
    return ecbCipher(key, data, length, xteaEncrypt);
}

/**
 * \brief   Function that decrypts data in ECB mode.
 *          In this mode, the amount of data MUST be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 *
 * \return  Function returns false when length of passed data is NOT a multiple of the data block,
 *          otherwise it returns true. Processed data is returned by the 'data' parameter.
 */
boolean XteaCipher::ecbDecrypt(const uint8_t key[XTEA_KEY_SIZE], uint8_t data[], const uint32_t length)
{
    return ecbCipher(key, data, length, xteaDecrypt);
}

/**
 * \brief   A function that encrypts data in CFB mode.
 *          In this mode, the amount of data does NOT need to be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in]       iv          64-bit [8 bytes] random initialization vector, a.k.a. nonce - number used once.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 *
 * \return Processed data is returned by the 'data' parameter.
 */
void XteaCipher::cfbEncrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_IV_SIZE], uint8_t data[], const uint32_t length)
{
    feedbackCipher(key, iv, data, length, xteaEncrypt, true);
}

/**
 * \brief   A function that decrypts data in CFB mode.
 *          In this mode, the amount of data does NOT need to be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in]       iv          64-bit [8 bytes] random initialization vector, a.k.a. nonce - number used once.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 *
 * \return Processed data is returned by the 'data' parameter.
 */
void XteaCipher::cfbDecrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_IV_SIZE], uint8_t data[], const uint32_t length)
{
    feedbackCipher(key, iv, data, length, xteaDecrypt, true);
}

/**
 * \brief   A function that encrypts data in OFB mode.
 *          In this mode, the amount of data does NOT need to be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in]       iv          64-bit [8 bytes] random initialization vector, a.k.a. nonce - number used once.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 *
 * \return Processed data is returned by the 'data' parameter.
 */
void XteaCipher::ofbEncrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_IV_SIZE], uint8_t data[], const uint32_t length)
{
    feedbackCipher(key, iv, data, length, xteaEncrypt, false);
}

/**
 * \brief   A function that decrypts data in OFB mode.
 *          In this mode, the amount of data does NOT need to be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in]       iv          64-bit [8 bytes] random initialization vector, a.k.a. nonce - number used once.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 *
 * \return Processed data is returned by the 'data' parameter.
 */
void XteaCipher::ofbDecrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_IV_SIZE], uint8_t data[], const uint32_t length)
{
    feedbackCipher(key, iv, data, length, xteaDecrypt, false);
}

/**
 * \brief A function that calculates MAC code for passed data.
 * 
 * \param[in]   key     128-bit [16 bytes] XTEA key.
 * \param[out]  mac     Calculated MAC code.
 * \param[in]   data    Data for which MAC code is to be calculated.
 * \param[in]   length  The amount of data for which MAC code is to be calculated (in bytes).
 * 
 * \return Values are returned by the 'mac' parameter.
 */
void XteaCipher::macCompute(const uint8_t key[XTEA_KEY_SIZE], uint8_t mac[XTEA_BLOCK_SIZE], const uint8_t data[], const uint32_t length)
{
    xteaCfbMacInit(&_ctx, key, _macRounds);
    xteaCfbMacUpdate(&_ctx, data, length);
    xteaCfbMacFinish(&_ctx);
    xteaCfbMacGet(&_ctx, mac);
}

/**
 * \brief A function that checks validity of MAC code for passed data.
 * 
 * \param[in]   key     128-bit [16 bytes] XTEA key.
 * \param[in]   mac     MAC code to compare with code calculated from passed data.
 * \param[in]   data    Data for which MAC code is to be calculated.
 * \param[in]   length  The amount of data for which MAC code is to be calculated (in bytes).
 * 
 * \return true - if MAC codes match, otherwise returns false.
 */
boolean XteaCipher::macVerify(const uint8_t key[XTEA_KEY_SIZE], const uint8_t mac[XTEA_BLOCK_SIZE], const uint8_t data[], const uint32_t length)
{
    xteaCfbMacInit(&_ctx, key, _macRounds);
    xteaCfbMacUpdate(&_ctx, data, length);
    xteaCfbMacFinish(&_ctx);

    return xteaCfbMacCmp(&_ctx, mac);
}

// ----------------------------------------------------------------
// |                    low level MAC functions                   |
// ----------------------------------------------------------------

/**
 * \brief   A function that initializes internal XTEA context by the passed data,
 *          for MAC code calculation operation (MAC - message authentication code).
 *          Two dependent keys (with large Hamming distance) are
 *          internally generated from passed key, which allows the same key
 *          to be used for both encryption and MAC code calculation operations.
 *
 * \param[in]   key     128-bit [16 bytes] XTEA key.
 *
 * \return nothing
 */
void XteaCipher::macInit(const uint8_t key[XTEA_KEY_SIZE])
{
    xteaCfbMacInit(&_ctx, key, _macRounds);
}

/**
 * \brief Add data to an initialized MAC calculation.
 *
 * \param[in]   data    Data to be added.
 * \param[in]   length  Size of the data to be added in bytes.
 *
 * \return nothing
 */
void XteaCipher::macUpdate(const uint8_t data[], const uint32_t length)
{
    xteaCfbMacUpdate(&_ctx, data, length);
}

/**
 * \brief Finish a MAC operation returning the MAC value.
 *
 * \return Computed MAC code is in 'data' field of internal XTEA context.
 */
void XteaCipher::macFinish(void)
{
    xteaCfbMacFinish(&_ctx);
}

/**
 * \brief   Function extracts computed MAC code from internal XTEA context
 *          and rewrites it to the 'mac' parameter.
 *
 * \param[out]  mac Calculated MAC code.
 *
 * \return Values are returned by the 'mac' parameter.
 */
void XteaCipher::macGet(uint8_t mac[XTEA_BLOCK_SIZE])
{
    xteaCfbMacGet(&_ctx, mac);
}

/**
 * \brief   A function that compares the indicated MAC code with
 *          code computed previously from passed data to check if they match.
 *
 * \param[in]   mac MAC code to compare with code stored in internal XTEA context.
 *
 * \return true - if MAC codes match, otherwise returns false.
 */
boolean XteaCipher::macCmp(const uint8_t mac[XTEA_BLOCK_SIZE])
{
    return xteaCfbMacCmp(&_ctx, mac);
}

// ----------------------------------------------------------------
// |                      private  functions                      |
// ----------------------------------------------------------------

/**
 * \brief   Function that encrypts/decrypts data in ECB mode.
 *          In this mode, the amount of data MUST be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 * \param[in]       operation   Operation to be performed: encryption/decryption.
 *
 * \return  Function returns 'false' when length of passed data is NOT a multiple of the data block,
 *          otherwise it returns 'true'. Processed data is returned by the 'data' parameter.
 */
boolean XteaCipher::ecbCipher(const uint8_t key[XTEA_KEY_SIZE], uint8_t data[], const uint32_t length, const xteaOperation_t operation)
{
    if((length % XTEA_BLOCK_SIZE) != 0)
    {
        return false;
    }

    _startPos       = 0;
    _remainingBytes = length / XTEA_BLOCK_SIZE;

    xteaInitEcb(&_ctx.cipher.base, key, _rounds);
    if(xteaDecrypt == operation)
    {
        xteaSetOperation(&_ctx.cipher.base, operation);
    }
    
    while(_remainingBytes--)
    {
        memcpy(&_ctx.data, data + _startPos, XTEA_BLOCK_SIZE);
        xteaEcbBlock(&_ctx.cipher.base, _ctx.data);
        memcpy(data + _startPos, &_ctx.data, XTEA_BLOCK_SIZE);
        _startPos += XTEA_BLOCK_SIZE;
    }

    return true;
}

/**
 * \brief   A function that encrypts/decrypts data in one of the feedback modes (CFB or OFB).
 *          In these modes, the amount of data does NOT need to be a multiple of the data block.
 *
 * \param[in]       key         128-bit [16 bytes] XTEA key.
 * \param[in]       iv          64-bit [8 bytes] random initialization vector, a.k.a. nonce - number used once.
 * \param[in,out]   data        Data to be processed by the function.
 * \param[in]       length      Amount of data to be processed by the function.
 * \param[in]       operation   Operation to be performed: encryption/decryption.
 * \param[in]       isCfb       Feedback mode selection: true for CFB mode, false for OFB mode.
 *
 * \return Values are returned by the 'data' parameter
 */
void XteaCipher::feedbackCipher    (const uint8_t key[XTEA_KEY_SIZE],
                                    const uint8_t iv[XTEA_IV_SIZE],
                                    uint8_t data[],
                                    const uint32_t length,
                                    const xteaOperation_t operation,
                                    const boolean isCfb)
{
    _startPos       = 0;

    uint8_t shift   {(length < XTEA_BLOCK_SIZE) ? length : XTEA_BLOCK_SIZE};

    xteaInit(&_ctx.cipher, key, iv, _rounds);
    if(xteaDecrypt == operation)
    {
        xteaSetOperation(&_ctx.cipher.base, operation);
    }

    while(shift)
    {
        memcpy(&_ctx.data, data + _startPos, shift);
        if(isCfb)
        {
            xteaCfbBlock(&_ctx.cipher, _ctx.data);
        } else
        {
            xteaOfbBlock(&_ctx.cipher, _ctx.data);
        }
        memcpy(data + _startPos, &_ctx.data, shift);

        _startPos += shift;
        _remainingBytes = length - _startPos;
        if(_remainingBytes < XTEA_BLOCK_SIZE)
        {
            shift = _remainingBytes;
        }
    }
}

// ----------------------------------------------------------------

/**
 * \brief An instance of the 'XteaCipher' class.
 */
XteaCipher xtea;

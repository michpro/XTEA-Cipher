/**
 * \file XTEATest_C_style.ino
 * \brief XTEA cipher library testing program (C style).
 *
 * \copyright SPDX-FileCopyrightText: Copyright 2020-2021 Michal Protasowicki
 *
 * \license SPDX-License-Identifier: MIT
 *
 */

#include "Arduino.h"
#include "xtea.h"

#if defined(__AVR_ATmega4808__)
#define Serial Serial1
#endif

void setup()
{
    Serial.begin(115200);
    Serial.println("Start tests... ('C' style)");

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, HIGH);

    uint8_t key[XTEA_KEY_SIZE] {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
    uint8_t iv[XTEA_IV_SIZE]   {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t data[]             {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
#if XTEA_ROUNDS == 48
    uint8_t encrEcb[]          {0x6C, 0xDE, 0x41, 0xA5, 0x51, 0xC1, 0xFA, 0x90, 0xFC, 0xF3, 0x69, 0x9D, 0x2D, 0x49, 0x64, 0x79,
                                0x48, 0xDE, 0x31, 0xAC, 0x3C, 0xBA, 0xE4, 0x41, 0x26, 0x02, 0xC2, 0xF6, 0xA9, 0xCA, 0x11, 0x07,
                                0x5C, 0xF2, 0xC4, 0xAA, 0xB3, 0xEA, 0x6C, 0xD7, 0x84, 0xAF, 0xDF, 0xBA, 0x1E, 0x61, 0xBA, 0x68,
                                0xE4, 0xB8, 0xCA, 0xC7, 0xD9, 0xF7, 0x08, 0x1A, 0x46, 0xBD, 0x0A, 0x37, 0x86, 0xD7, 0xF1, 0x45};

    uint8_t encrCfb[]          {0x74, 0xB1, 0x75, 0x6B, 0xBF, 0x26, 0xA3, 0x3F, 0x87, 0x0C, 0x21, 0x98, 0x71, 0x9F, 0x5D, 0x20,
                                0xAB, 0x6F, 0x70, 0xF9, 0x41, 0x46, 0x1D, 0x0B, 0x9B, 0x36, 0x0E, 0x29, 0xCD, 0x3E, 0xAF, 0x7B,
                                0xE6, 0xAD, 0x40, 0x22, 0xA0, 0xA3, 0xF7, 0x93, 0x84, 0x60, 0x05, 0xD3, 0x4A, 0xEE, 0xAF, 0x01,
                                0x3E, 0xD4, 0x08, 0x09, 0x32, 0x0D, 0xFE, 0xF3, 0xC1, 0x93, 0x45, 0x00, 0x0A, 0x7A, 0xB9, 0x27};

    uint8_t encrOfb[]          {0x74, 0xB1, 0x75, 0x6B, 0xBF, 0x26, 0xA3, 0x3F, 0x0A, 0x4E, 0x4F, 0xFF, 0x6B, 0xD3, 0xEA, 0x1E,
                                0x32, 0x0C, 0x9E, 0x7C, 0xCA, 0x9C, 0xAE, 0x28, 0xBB, 0x14, 0x87, 0xFF, 0xCA, 0xAE, 0x39, 0xF9,
                                0x3E, 0x56, 0x13, 0x34, 0x19, 0xD9, 0x8E, 0xD3, 0x49, 0x03, 0x5B, 0xF9, 0x0E, 0x4C, 0xE3, 0x94,
                                0x0E, 0x8D, 0xF0, 0xE3, 0x06, 0xBB, 0x2B, 0x5C, 0x59, 0x1A, 0xDE, 0x5B, 0x51, 0xA5, 0x7C, 0xB5};
#elif XTEA_ROUNDS == 32
    uint8_t encrEcb[]          {0x0E, 0xA2, 0x4F, 0x26, 0xCD, 0xDD, 0x01, 0x75, 0x4D, 0x3C, 0x3A, 0xCD, 0xC8, 0x01, 0x45, 0x77,
                                0x41, 0x0A, 0x49, 0xB8, 0xAD, 0xA5, 0x90, 0x0A, 0xD5, 0x83, 0xA5, 0xD7, 0xC0, 0xF0, 0x33, 0xA0,
                                0x09, 0xC5, 0xA5, 0xC3, 0x5D, 0x63, 0x76, 0xDC, 0x3C, 0x39, 0xCE, 0x44, 0xFF, 0x57, 0x45, 0x4C,
                                0xD2, 0xD8, 0x5A, 0x95, 0x03, 0x8C, 0x3B, 0x89, 0xCE, 0x59, 0xB7, 0x7C, 0x00, 0x2F, 0x6D, 0x80};

    uint8_t encrCfb[]          {0xEA, 0x1A, 0x8B, 0xF2, 0xD1, 0x8D, 0xBF, 0xBC, 0xA6, 0x83, 0x9E, 0xAF, 0x92, 0x3C, 0x0B, 0x2A,
                                0x20, 0xA3, 0x21, 0xC1, 0x85, 0x8F, 0xA0, 0xE6, 0x03, 0x72, 0x4D, 0xD6, 0x5C, 0xB2, 0x1C, 0x2A,
                                0xEE, 0x9D, 0x42, 0x07, 0xED, 0x1C, 0x31, 0xE3, 0x43, 0x41, 0x77, 0xB7, 0xA2, 0x5B, 0xA6, 0xEB,
                                0xED, 0xB7, 0x04, 0xC9, 0xBB, 0x15, 0xEC, 0xE3, 0xDB, 0x67, 0xDE, 0x0F, 0xA8, 0xC5, 0x09, 0xB4};

    uint8_t encrOfb[]          {0xEA, 0x1A, 0x8B, 0xF2, 0xD1, 0x8D, 0xBF, 0xBC, 0x99, 0xC6, 0x96, 0xB8, 0x05, 0x93, 0xBD, 0xDB,
                                0xA5, 0xDA, 0x81, 0xFB, 0x2A, 0x50, 0x35, 0x77, 0xCB, 0x28, 0xD4, 0x3F, 0x78, 0x71, 0xE9, 0x07,
                                0x08, 0x79, 0xEF, 0x9F, 0xB0, 0x22, 0x5E, 0xA3, 0x9F, 0xB1, 0x6D, 0xB0, 0x2E, 0x4D, 0x75, 0x49,
                                0x8F, 0x93, 0x26, 0x7E, 0x58, 0x16, 0x42, 0x45, 0xB7, 0x05, 0x56, 0x27, 0xE3, 0xA7, 0xAD, 0x0F};
#elif XTEA_ROUNDS == 24
    uint8_t encrEcb[]          {0xC2, 0x5E, 0x11, 0x24, 0xCE, 0x27, 0x92, 0x07, 0xDD, 0x2A, 0x4D, 0x69, 0xD0, 0x45, 0xA2, 0xF8,
                                0x9B, 0x82, 0x64, 0xC5, 0x88, 0x50, 0x40, 0x07, 0xC0, 0xCD, 0x97, 0x41, 0x6A, 0xD7, 0x3F, 0xC5,
                                0x72, 0x95, 0xBB, 0xF4, 0xDB, 0xCE, 0x6B, 0x9B, 0xD9, 0x93, 0x7F, 0x75, 0x4B, 0x33, 0x5F, 0xFB,
                                0x20, 0x06, 0x89, 0xC6, 0xC8, 0xE8, 0x6C, 0xFF, 0x85, 0x08, 0xCD, 0x13, 0x36, 0x93, 0x1E, 0xC1};

    uint8_t encrCfb[]          {0xB1, 0x2D, 0x1C, 0x4B, 0x16, 0x89, 0x41, 0xBD, 0x6E, 0x87, 0xBF, 0xCF, 0x5F, 0x71, 0x5E, 0x86,
                                0x1C, 0x7A, 0x8B, 0x18, 0xFD, 0x3E, 0x03, 0x28, 0x60, 0x2B, 0x27, 0xFF, 0x2D, 0xE2, 0x47, 0xFC,
                                0x25, 0x29, 0xE0, 0x98, 0xB3, 0x71, 0x53, 0x2B, 0xF5, 0x03, 0x9A, 0x3A, 0x24, 0x90, 0xD1, 0x83,
                                0xA8, 0xD5, 0x5D, 0xE4, 0xA8, 0x47, 0x9C, 0xE1, 0xD3, 0x1B, 0x9F, 0x4D, 0x4E, 0xD6, 0xD3, 0xB2};

    uint8_t encrOfb[]          {0xB1, 0x2D, 0x1C, 0x4B, 0x16, 0x89, 0x41, 0xBD, 0x73, 0x7B, 0xC6, 0x31, 0xCA, 0xF5, 0x99, 0x08,
                                0x3C, 0x6D, 0xBD, 0x76, 0x30, 0x39, 0x9B, 0xF7, 0xD2, 0xFA, 0x13, 0xAA, 0x6F, 0x7B, 0xFF, 0x4B,
                                0xC8, 0x02, 0x75, 0x1D, 0xDB, 0x09, 0xE0, 0x74, 0xCD, 0x85, 0x04, 0x8E, 0x7F, 0x5F, 0xA3, 0x18,
                                0xD5, 0x9F, 0x69, 0xA0, 0xE6, 0xCC, 0x57, 0xCE, 0x31, 0x7A, 0x6C, 0x92, 0x67, 0x91, 0x88, 0xDD};
#else
    uint8_t encrEcb[sizeof(data)] {0x00};
    uint8_t encrCfb[sizeof(data)] {0x00};
    uint8_t encrOfb[sizeof(data)] {0x00};
#endif

    uint8_t encrData[]         {0xEA, 0x1A, 0x8B, 0xF2, 0xD1, 0x8D, 0xBF, 0xBC, 0xA6, 0x83, 0x9E, 0xAF, 0x92, 0x3C, 0x0B, 0x2A,
                                0x20, 0xA3, 0x21, 0xC1, 0x85, 0x8F, 0xA0, 0xE6, 0x03, 0x72, 0x4D, 0xD6, 0x5C, 0xB2, 0x1C, 0x2A,
                                0xEE, 0x9D, 0x42, 0x07, 0xED, 0x1C, 0x31, 0xE3, 0x43, 0x41, 0x77, 0xB7, 0xA2, 0x5B, 0xA6, 0xEB,
                                0xED, 0xB7, 0x04, 0xC9, 0xBB, 0x15, 0xEC, 0xE3, 0xDB, 0x67, 0xDE, 0x0F, 0xA8, 0xC5, 0x09, 0xB4};

#if XTEA_MAC_ROUNDS == 32
    uint8_t mac7Bytes[]        {0x7D, 0x8F, 0xE6, 0xDD, 0x6C, 0x27, 0x80, 0x36};
    uint8_t macAllBytes[]      {0x47, 0x0C, 0xD1, 0x9F, 0x44, 0x2D, 0xFC, 0xD9};
    uint8_t macAADCiph[]       {0x72, 0x0D, 0x46, 0xB4, 0xD4, 0x51, 0xA8, 0xAD};
#elif XTEA_MAC_ROUNDS == 24
    uint8_t mac7Bytes[]        {0xAA, 0xA0, 0x81, 0xB0, 0xEB, 0xC2, 0x0E, 0x43};
    uint8_t macAllBytes[]      {0x36, 0x38, 0xA7, 0xF5, 0xED, 0xD3, 0x73, 0x6A};
    uint8_t macAADCiph[]       {0x3E, 0x5C, 0x43, 0xC0, 0x12, 0xE9, 0x12, 0x08};
#elif XTEA_MAC_ROUNDS == 20
    uint8_t mac7Bytes[]        {0x7D, 0x18, 0xA1, 0x45, 0x16, 0x15, 0xB3, 0x60};
    uint8_t macAllBytes[]      {0x2D, 0xFA, 0x79, 0x7B, 0x17, 0x59, 0xFF, 0x5F};
    uint8_t macAADCiph[]       {0x29, 0x6E, 0x6D, 0xC1, 0xC1, 0x5B, 0x26, 0xBB};
#else
    uint8_t mac7Bytes[]        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t macAllBytes[]      {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t macAADCiph[]       {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

    uint8_t     resultBuffer[sizeof(data)];
    uint8_t     block[XTEA_BLOCK_SIZE] {0};
    uint32_t    start;
    uint32_t    time;
    uint8_t     chunks  = sizeof(data) / XTEA_BLOCK_SIZE;
    uint8_t     shift   = 0;

    String      timeStr = " time [us]: ";
    String      tiblStr = " time [us]/block: ";
    String      usStr   = ") [us]: ";
    String      chkStr  = "\t Checking data with test vector: ";
    String      encStr  = "Encrypt";
    String      decStr  = "Decrypt";
    String      pasStr  = "PASS";
    String      faiStr  = "FAIL";
    String      allStr  = " ALL loops (n = ";
    String      cfbMac  = "CFB-MAC";
    String      resultStr;

//----------------------------------------------------

    Serial.println("XTEA_ROUNDS = " + String(XTEA_ROUNDS) + "   XTEA_MAC_ROUNDS = " + String(XTEA_MAC_ROUNDS));

    Serial.println("ECB:");

    xteaEcbCtx_t ctxEcb;

    xteaInitEcb(&ctxEcb, key, XTEA_ROUNDS);                         // initialization of the ECB context
    
    start = micros();
    shift = 0;
    for (uint8_t i = 0; i < chunks; i++)                            // encryption in ECB mode
    {
        memcpy(block, data + shift, XTEA_BLOCK_SIZE);               // copying data block into buffer
        xteaEcbBlock(&ctxEcb, block);                               // data block encryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying encrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after encryption with reference data and print results
    Serial.print(encStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, encrEcb, sizeof(encrEcb))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);

    start = micros();
    shift = 0;
    xteaSetOperation(&ctxEcb, xteaDecrypt);                         // setting the decryption operation
    for (uint8_t i = 0; i < chunks; i++)                            // decryption in ECB mode
    {
        memcpy(block, resultBuffer + shift, XTEA_BLOCK_SIZE);       // copying data block into buffer
        xteaEcbBlock(&ctxEcb, block);                               // data block decryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying decrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after decryption with reference data and print results
    Serial.print(decStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, data, sizeof(data))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);
    Serial.println("");

//----------------------------------------------------
    
    Serial.println("CFB:");

    xteaCipherCtx_t ctx;

    xteaInit(&ctx, key, iv, XTEA_ROUNDS);                           // initialization of the Cipher context

    start = micros();
    shift = 0;
    for (uint8_t i = 0; i < chunks; i++)                            // encryption in CFB mode
    {
        memcpy(block, data + shift, XTEA_BLOCK_SIZE);               // copying data block into buffer
        xteaCfbBlock(&ctx, block);                                  // data block encryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying encrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after encryption with reference data and print results
    Serial.print(encStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, encrCfb, sizeof(encrCfb))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);

    start = micros();
    shift = 0;
    xteaSetIv(&ctx, iv);                                            // re-initialization of IV vector (cipher operations in this mode constantly modify IV vector)
    xteaSetOperation(&ctx.base, xteaDecrypt);                       // setting the decryption operation
    for (uint8_t i = 0; i < chunks; i++)                            // decryption in CFB mode
    {
        memcpy(block, resultBuffer + shift, XTEA_BLOCK_SIZE);       // copying data block into buffer
        xteaCfbBlock(&ctx, block);                                  // data block decryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying decrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after decryption with reference data and print results
    Serial.print(decStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, data, sizeof(data))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);
    Serial.println("");

//----------------------------------------------------
    
    Serial.println("OFB:");

    start = micros();
    shift = 0;
    xteaSetIv(&ctx, iv);                                            // re-initialization of IV vector (OFB and CFB modes use the same context)
    xteaSetOperation(&ctx.base, xteaEncrypt);                       // setting the encryption operation
    for (uint8_t i = 0; i < chunks; i++)                            // encryption in OFB mode
    {
        memcpy(block, data + shift, XTEA_BLOCK_SIZE);               // copying data block into buffer
        xteaOfbBlock(&ctx, block);                                  // data block encryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying encrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after encryption with reference data and print results
    Serial.print(encStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, encrOfb, sizeof(encrOfb))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);

    start = micros();
    shift = 0;

    xteaSetIv(&ctx, iv);                                            // re-initialization of IV vector (cipher operations in this mode constantly modify IV vector)
    xteaSetOperation(&ctx.base, xteaDecrypt);                       // setting the decryption operation
    for (uint8_t i = 0; i < chunks; i++)                            // decryption in OFB mode
    {
        memcpy(block, resultBuffer + shift, XTEA_BLOCK_SIZE);       // copying data block into buffer
        xteaOfbBlock(&ctx, block);                                  // data block decryption
        memcpy(resultBuffer + shift, block, XTEA_BLOCK_SIZE);       // copying decrypted data
        shift += XTEA_BLOCK_SIZE;
    }
    time = micros() - start;

    // compare the contents of buffer after decryption with reference data and print results
    Serial.print(decStr + tiblStr + String(time / chunks));
    resultStr = (0 == memcmp(resultBuffer, data, sizeof(data))) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);
    Serial.println("");

//----------------------------------------------------

    // Function tests for calculating MAC codes.
    Serial.println(cfbMac + ":");

    xteaCtx_t       mCtx;
    uint_fast16_t   counts = 1000;

    start = micros();
    for (uint_fast16_t i = 0; i < counts; i++)
    {
        xteaCfbMacInit(&mCtx, key, XTEA_MAC_ROUNDS);                // context initialization for MAC functions
        __asm__ volatile("");    // prevents compiler from optimizing loop
    }
    time = micros() - start;

    Serial.println(cfbMac + " init" + timeStr + String(time / counts) + "\t\t\t\t\t" + allStr + String(counts) + usStr + String(time));

    start = micros();
    for (uint_fast16_t i = 0; i < counts; i++)
    {
       xteaCfbMacUpdate(&mCtx, data, XTEA_BLOCK_SIZE);              // updating MAC code calculations for new data
       __asm__ volatile("");    // prevents compiler from optimizing loop
    }
    time = micros() - start;

    Serial.println(cfbMac + " update" + timeStr + String(time / counts) + "\t\t\t\t" + allStr + String(counts) + usStr + String(time));

    start = micros();
    for (uint_fast16_t i = 0; i < counts; i++)
    {
       xteaCfbMacFinish(&mCtx);                                     // calculating final MAC code after entering all data
       __asm__ volatile("");    // prevents compiler from optimizing loop
    }
    time = micros() - start;

    Serial.println(cfbMac + " finish [worst case]" + timeStr + String(time / counts) + "\t" + allStr + String(counts) + usStr + String(time));

    start = micros();
    for (uint_fast16_t i = 0; i < counts; i++)
    {
       xteaCfbMacGet(&mCtx, block);                                 // fetching MAC code from context
       __asm__ volatile("");    // prevents compiler from optimizing loop
    }
    time = micros() - start;

    Serial.println(cfbMac + " get MAC" + timeStr + String(time / counts) + "\t\t\t\t" + allStr + String(counts) + usStr + String(time));

    start = micros();
    for (uint_fast16_t i = 0; i < counts; i++)
    {
       xteaCfbMacCmp(&mCtx, block);                                 // verification of passed MAC code with the previously calculated
                                                                    // on the basis of passed data
       __asm__ volatile("");    // prevents compiler from optimizing loop
    }
    time = micros() - start;

    Serial.println(cfbMac + " check MAC" + timeStr + String(time / counts) + "\t\t\t\t" + allStr + String(counts) + usStr + String(time));
    Serial.println("");

//----------------------------------------------------

    // calculating and verifying a MAC code for data in an amount less than one complete data block.
    start = micros();
    xteaCfbMacInit(&mCtx, key, XTEA_MAC_ROUNDS);
    xteaCfbMacUpdate(&mCtx, data, 7);
    xteaCfbMacFinish(&mCtx);
    xteaCfbMacGet(&mCtx, block);
    time = micros() - start;

    Serial.print(cfbMac + " (7 bytes data)" + tiblStr + String(time));
    resultStr = xteaCfbMacCmp(&mCtx, mac7Bytes) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);

    // MAC code calculation and verification for more data
    start = micros();
    xteaCfbMacInit(&mCtx, key, XTEA_MAC_ROUNDS);
    xteaCfbMacUpdate(&mCtx, data, sizeof(data));
    xteaCfbMacFinish(&mCtx);
    xteaCfbMacGet(&mCtx, block);
    time = micros() - start;

    Serial.print(cfbMac + " (all bytes data)" + tiblStr + String(time / (chunks + 1)));
    resultStr = xteaCfbMacCmp(&mCtx, macAllBytes) ? pasStr : faiStr;
    Serial.println(chkStr + resultStr);

//----------------------------------------------------

    Serial.print(cfbMac + " code authentication of unencrypted data and cryptogram:");

    // MAC code calculation and verification for combined unencrypted and encrypted data.
    uint32_t    dataSize    {toBigEndian(sizeof(iv))};              // Change in endianity so that the data for calculating the MAC code
                                                                    // is the same on devices having different endianities.
    uint8_t   * dPtr        {(uint8_t *)&dataSize};                 // allows access to uint_32_t variable as uint8_t[]

    xteaCfbMacInit(&mCtx, key, XTEA_MAC_ROUNDS);                    // context initialization for MAC function
    xteaCfbMacUpdate(&mCtx, dPtr, sizeof(uint32_t));                // MAC code calculation for unencrypted data
    xteaCfbMacUpdate(&mCtx, iv, sizeof(iv));
    dataSize = toBigEndian(sizeof(encrData));                       // continue MAC code calculation for encrypted data
    xteaCfbMacUpdate(&mCtx, dPtr, sizeof(uint32_t));
    xteaCfbMacUpdate(&mCtx, encrData, sizeof(encrData));
    xteaCfbMacFinish(&mCtx);                                        // calculating final MAC code after entering all data
    xteaCfbMacGet(&mCtx, block);                                    // fetching MAC code from context

    resultStr = xteaCfbMacCmp(&mCtx, macAADCiph) ? pasStr : faiStr; // verification of passed MAC code with the previously calculated
    Serial.println(chkStr + resultStr);

    Serial.println("End tests.");
}

// the loop function runs over and over again forever
void loop()
{
    digitalWrite(LED_BUILTIN, HIGH);
    delay(50);
    digitalWrite(LED_BUILTIN, LOW);
    delay(1950);
}

//----------------------------------------------------

uint32_t toBigEndian(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(x);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return x;
#else
    #error "Unsupported hardware !!!" 
#endif
}

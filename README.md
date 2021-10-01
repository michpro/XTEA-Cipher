# XTEA-Cipher library for Arduino

XTEA cipher library with MAC code calculation support for Arduino environment. Supported encryption modes are: ECB, CFB and OCB and for generating message authentication codes is CFB-MAC. 'C' code of this library was optimized for lowest possible use of program memory. Contrary to reference implementation, base data type is uint8_t[] instead of uint_32_t. 

---

## Constants

Configure library settings in file `xtea.h`, or better in your sketch, by adding directive `#define XTEA_ROUNDS n ` or/and `#define XTEA_MAC_ROUNDS n ` before directive including this cipher library e.g.:
```c
...
#define XTEA_ROUNDS 48
#define XTEA_MAC_ROUNDS 24

#include "XTEA-Cipher.h"
...
```

- **XTEA_ROUNDS**

  actual number of Feistel rounds during cipher is `2 * XTEA_ROUNDS`

  [default value is `32`]

- **XTEA_MAC_ROUNDS**
  
  actual number of Feistel rounds during MAC calculation is `2 * XTEA_MAC_ROUNDS`

  [default value is `32`]
  
  ---
  known attack is on 36 Feistel rounds (18 `XTEA_ROUNDS` or `XTEA_MAC_ROUNDS`)

- **XTEA_BLOCK_SIZE**
  
  data block size = 64-bit [8 bytes]

  [*Do NOT change its value*]

- **XTEA_IV_SIZE**
  
  size of initialization vector [IV] (a.k.a. NONCE) = 64-bit [8 bytes]

  [*Do NOT change its value*]

- **XTEA_KEY_SIZE**
  
  key size = 128-bit [16 bytes]

  [*Do NOT change its value*]

---

## Library Content

**Read the source code for details.**

---

## Examples

- [XTEA Test 'C' style](examples/XTEATest_C_style/XTEATest_C_style.ino)
  
  Sketch shows examples of calling 'C' code functions and validating them with test vectors.

- [XTEA Test Arduino style](examples/XTEATest_Arduino_style/XTEATest_Arduino_style.ino)
  
  This sketch shows examples of calling methods of a c++ class and validating them with test vectors.

---

## Installation Guide

[Arduino IDE](https://www.arduino.cc/en/Main/Software) -
[Additional libraries installation guide](https://www.arduino.cc/en/Guide/Libraries).

---

## Reporting bugs

[Create an issue on GitHub](https://github.com/michpro/XTEA-Cipher/issues).

---

# License
Copyright © 2020-2021 Michal Protasowicki

Source: https://github.com/michpro/XTEA-Cipher

This project is released under MIT License.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

# Support
If You find my projects interesting and You wanted to support my work, You can give me a cup of coffee or a keg of beer :)

[![PayPal Direct](https://badgen.net/badge/icon/Support%20me%20by%20PayPal?icon=kofi&label&scale=1.5&color=blue)](https://www.paypal.me/michpro)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[![ko-fi](https://badgen.net/badge/icon/Support%20me%20on%20Ko-fi?icon=kofi&label&scale=1.5&color=red)](https://ko-fi.com/F1F24CEW1)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[![Coinbase](https://badgen.net/badge/icon/Support%20me%20with%20cryptocurrencies?icon=kofi&label&scale=1.5&color=blue)](https://commerce.coinbase.com/checkout/ec299320-cbed-475d-976e-fdf37c1ac3d0)
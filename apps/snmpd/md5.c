/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla <kurilo@gmail.com>
 *
 * This program is part of free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#include "md5.h"

/**
 *  MD5 implementation derived from the RSA Data Security, Inc. MD5 Message Digest Algorithm.
 */

#if ENABLE_SNMPv3 && ENABLE_AUTH

/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* forward declaration */
static void Transform (UINT4 *buf, UINT4 *in);

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (MD5_CTX *mdContext)
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (MD5_CTX *mdContext, u8t *inBuf, u16t inLen)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (MD5_CTX *mdContext, u8t* digest)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  
  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  u8t padChar = 0x80;
  MD5Update (mdContext, &padChar, 1);
  padChar = 0x00;
  for (i = 0; i < padLen - 1; i++) {
    MD5Update (mdContext, &padChar, 1);
  }

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    digest[ii+1] = (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    digest[ii+2] = (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    digest[ii+3] = (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (UINT4 *buf, UINT4 *in)
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 0xD76AA478); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756); /* 2 */
  FF ( c, d, a, b, in[ 2], S13, 0x242070DB); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEE); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAF); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 0x4787C62A); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 0xA8304613); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 0xFD469501); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 0x698098D8); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AF); /* 10 */
  FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1); /* 11 */
  FF ( b, c, d, a, in[11], S14, 0x895CD7BE); /* 12 */
  FF ( a, b, c, d, in[12], S11, 0x6B901122); /* 13 */
  FF ( d, a, b, c, in[13], S12, 0xFD987193); /* 14 */
  FF ( c, d, a, b, in[14], S13, 0xA679438E); /* 15 */
  FF ( b, c, d, a, in[15], S14, 0x49B40821); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 0xF61E2562); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 0xC040B340); /* 18 */
  GG ( c, d, a, b, in[11], S23, 0x265E5A51); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AA); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 0xD62F105D); /* 21 */
  GG ( d, a, b, c, in[10], S22, 0x02441453); /* 22 */
  GG ( c, d, a, b, in[15], S23, 0xD8A1E681); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8); /* 24 */
  GG ( a, b, c, d, in[ 9], S21, 0x21E1CDE6); /* 25 */
  GG ( d, a, b, c, in[14], S22, 0xC33707D6); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 0x455A14ED); /* 28 */
  GG ( a, b, c, d, in[13], S21, 0xA9E3E905); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 0x676F02D9); /* 31 */
  GG ( b, c, d, a, in[12], S24, 0x8D2A4C8A); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 0x8771F681); /* 34 */
  HH ( c, d, a, b, in[11], S33, 0x6D9D6122); /* 35 */
  HH ( b, c, d, a, in[14], S34, 0xFDE5380C); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60); /* 39 */
  HH ( b, c, d, a, in[10], S34, 0xBEBFBC70); /* 40 */
  HH ( a, b, c, d, in[13], S31, 0x289B7EC6); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 0xEAA127FA); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085); /* 43 */
  HH ( b, c, d, a, in[ 6], S34, 0x04881D05); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039); /* 45 */
  HH ( d, a, b, c, in[12], S32, 0xE6DB99E5); /* 46 */
  HH ( c, d, a, b, in[15], S33, 0x1FA27CF8); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 0xF4292244); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 0x432AFF97); /* 50 */
  II ( c, d, a, b, in[14], S43, 0xAB9423A7); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 0xFC93A039); /* 52 */
  II ( a, b, c, d, in[12], S41, 0x655B59C3); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92); /* 54 */
  II ( c, d, a, b, in[10], S43, 0xFFEFF47D); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 0x85845DD1); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 0x6FA87E4F); /* 57 */
  II ( d, a, b, c, in[15], S42, 0xFE2CE6E0); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 0xA3014314); /* 59 */
  II ( b, c, d, a, in[13], S44, 0x4E0811A1); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 0xF7537E82); /* 61 */
  II ( d, a, b, c, in[11], S42, 0xBD3AF235); /* 62 */
  II ( c, d, a, b, in[ 2], S43, 0x2AD7D2BB); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 0xEB86D391); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}
#endif
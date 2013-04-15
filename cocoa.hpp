/*
 * Cocoa, an amalgamation of hashing algorithms.
 * CRC32, GCRC, RS, JS, PJW, ELF, BKDR, SBDM, DJB, DJB2, BP, FNV, AP, BJ1, MH2, SHA1
 * Copyright (c) 2010 Mario 'rlyeh' Rodriguez

 * This source file is basetyped on code from Arash Partow (http://www.partow.net)
 * plus the original and credited authors for each algorithm. Thanks everybody!

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.

 * To do:
 * - add comparison operators (>,<=,>=)
 * - add adler32 hashing
 * - add perfect hashing ( ref: http://cmph.sourceforge.net/index.html || http://burtleburtle.net/bob/hash/perfect.html )
 * - add boost hashing: seed ^= hash_value(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

 * - rlyeh
 */

#pragma once

#include <cassert>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <cstdint>

namespace cocoa
{
    typedef std::uint32_t basetype;

    class hash
    {
        std::vector<basetype> h;

        public:

        explicit
        hash( basetype bits ) : h(bits/32, 0)
        {}

        hash( basetype bits, const basetype &A ): h(bits/32)
        { h[0] = A; }

        hash( basetype bits, const basetype &A, const basetype &B ): h(bits/32)
        { h[0] = A, h[1] = B; }

        hash( basetype bits, const basetype &A, const basetype &B, const basetype &C ): h(bits/32)
        { h[0] = A, h[1] = B, h[2] = C; }

        hash( basetype bits, const basetype &A, const basetype &B, const basetype &C, const basetype &D ): h(bits/32)
        { h[0] = A, h[1] = B, h[2] = C, h[3] = D; }

        hash( basetype bits, const basetype &A, const basetype &B, const basetype &C, const basetype &D, const basetype &E ): h(bits/32)
        { h[0] = A, h[1] = B, h[2] = C, h[3] = D, h[4] = E; }


        inline basetype &operator []( basetype i )
        {
            return h[i];
        }
        inline const basetype &operator []( basetype i ) const
        {
            return h[i];
        }

        inline const bool operator ==( const hash &t ) const
        {
            return h == t.h;
        }

        inline const bool operator !=( const hash &t ) const
        {
            return h != t.h;
        }

        inline const bool operator<( const hash &t ) const
        {
            return h < t.h;
        }

        inline const bool operator ==( const std::string &t ) const
        {
            return str() == t;
        }

        inline const bool operator<( const std::string &t ) const
        {
            return str() < t;
        }

        size_t size() const
        {
            return h.size();
        }

        const void *data() const
        {
            return h.data();
        }

        void *data()
        {
            return h.data();
        }

        std::vector<basetype>::iterator begin() { return h.begin(); }
        std::vector<basetype>::iterator   end() { return h.end(); }
        std::vector<basetype>::const_iterator begin() const { return h.begin(); }
        std::vector<basetype>::const_iterator   end() const { return h.end(); }

        operator std::string() const
        {
            return str();
        }

        std::string str() const
        {
            std::string out;

            for( std::vector<basetype>::const_iterator it = h.begin(); it != h.end(); ++it )
            {
                std::stringstream ss;
                std::string s;
                ss << std::hex << std::setfill('0') << std::setw(8) << (*it);
                ss >> s;
                out += s;
            }

            return out;
        }

        std::vector<unsigned char> blob() const
        {
            std::vector<unsigned char> blob;

            for( std::vector<basetype>::const_iterator it = h.begin(); it != h.end(); ++it )
            {
                static int i = 1;
                static char *low = (char*)&i;
                static bool is_big = ( *low ? false : true );

                if( is_big )
                    for( int i = 0; i < sizeof(basetype); ++i )
                        blob.push_back( ( (*it) >> (i * 8) ) & 0xff );
                else
                    for( int i = sizeof(basetype) - 1; i >= 0; --i )
                        blob.push_back( ( (*it) >> (i * 8) ) & 0xff );
            }

            return blob;
        }

        public:

        static hash CRC32( const void *pMem, size_t iLen, hash my_hash = hash(32,0) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            static const basetype crcTable[16] =
            {
                0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
                0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
                0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
                0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
            };

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype h = ~my_hash[0];

            while( iLen-- )
            {
                h ^= (*pPtr++);
                h = crcTable[h & 0x0f] ^ (h >> 4);
                h = crcTable[h & 0x0f] ^ (h >> 4);
            }

            return hash( 32, ~h );
        }

        template< typename T >
        static hash CRC32( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return CRC32( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash CRC32( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return CRC32( input, input ? strlen(input) : 0, my_hash );
        }

        // Generalized CRC (less collisions), Bob Jenkins
        static hash GCRC( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            static const basetype crcTable[256] =
            {
                0x46D1E192,0x66EDF9AA,0x927FC9E5,0xA53BAACC,0x29B47658,0x5A411A01,0x0E66D5BD,
                0x0DD5B1DB,0xCB38340E,0x04D4EBB6,0x98BC4F54,0x36F20F2C,0x4A3047ED,0x1EC1E0EB,
                0x568C0C1F,0x6A731432,0x81367FC6,0xE3E25237,0xE7F64884,0x0FA59F64,0x4F3109DE,
                0xF02D61F5,0x5DAEC03B,0x7F740E83,0x056FF2D8,0x2026CC0A,0x7AC2112D,0x82C55605,
                0xB0911EF2,0xA7B88E4C,0x89DCA282,0x4B254D27,0x7694A6D3,0xD229EADD,0x8E8F3738,
                0x5BEE7A55,0x012EB6AB,0x08DD28C8,0xB5ABC274,0xBC7931F0,0xF2396ED5,0xE4E43D97,
                0x943F4B7F,0x85D0293D,0xAED83A88,0xC8F932FC,0xC5496F20,0xE9228173,0x9B465B7D,
                0xFDA26680,0x1DDEAB35,0x0C4F25CB,0x86E32FAF,0xE59FA13A,0xE192E2C4,0xF147DA1A,
                0x67620A8D,0x5C9A24C5,0xFE6AFDE2,0xACAD0250,0xD359730B,0xF35203B3,0x96A4B44D,
                0xFBCACEA6,0x41A165EC,0xD71E53AC,0x835F39BF,0x6B6BDE7E,0xD07085BA,0x79064E07,
                0xEE5B20C3,0x3B90BD65,0x5827AEF4,0x4D12D31C,0x9143496E,0x6C485976,0xD9552733,
                0x220F6895,0xE69DEF19,0xEB89CD70,0xC9BB9644,0x93EC7E0D,0x2ACE3842,0x2B6158DA,
                0x039E9178,0xBB5367D7,0x55682285,0x4315D891,0x19FD8906,0x7D8D4448,0xB4168A03,
                0x40B56A53,0xAA3E69E0,0xA25182FE,0xAD34D16C,0x720C4171,0x9DC3B961,0x321DB563,
                0x8B801B9E,0xF5971893,0x14CC1251,0x8F4AE962,0xF65AFF1E,0x13BD9DEE,0x5E7C78C7,
                0xDDB61731,0x73832C15,0xEFEBDD5B,0x1F959ACA,0xE801FB22,0xA89826CE,0x30B7165D,
                0x458A4077,0x24FEC52A,0x849B065F,0x3C6930CD,0xA199A81D,0xDB768F30,0x2E45C64A,
                0xFF2F0D94,0x4EA97917,0x6F572ACF,0x653A195C,0x17A88C5A,0x27E11FB5,0x3F09C4C1,
                0x2F87E71B,0xEA1493E4,0xD4B3A55E,0xBE6090BE,0xAF6CD9D9,0xDA58CA00,0x612B7034,
                0x31711DAD,0x6D7DB041,0x8CA786B7,0x09E8BF7A,0xC3C4D7EA,0xA3CD77A8,0x7700F608,
                0xDF3DE559,0x71C9353F,0x9FD236FB,0x1675D43E,0x390D9E9A,0x21BA4C6B,0xBD1371E8,
                0x90338440,0xD5F163D2,0xB140FEF9,0x52F50B57,0x3710CF67,0x4C11A79C,0xC6D6624E,
                0x3DC7AFA9,0x34A69969,0x70544A26,0xF7D9EC98,0x7C027496,0x1BFB3BA3,0xB3B1DC8F,
                0x9A241039,0xF993F5A4,0x15786B99,0x26E704F7,0x51503C04,0x028BB3B8,0xEDE5600C,
                0x9CB22B29,0xB6FF339B,0x7E771C43,0xC71C05F1,0x604CA924,0x695EED60,0x688ED0BC,
                0x3E0B232F,0xF8A39C11,0xBAE6E67C,0xB8CF75E1,0x970321A7,0x5328922B,0xDEF3DF2E,
                0x8D0443B0,0x2885E3AE,0x6435EED1,0xCC375E81,0xA98495F6,0xE0BFF114,0xB2DA3E4F,
                0xC01B5ADF,0x507E0721,0x6267A36A,0x181A6DF8,0x7BAFF0C0,0xFA6D6C13,0x427250B2,
                0xE2F742D6,0xCD5CC723,0x2D218BE7,0xB91FBBB1,0x9EB946D0,0x1C180810,0xFC81D602,
                0x0B9C3F52,0xC2EA456F,0x1165B2C9,0xABF4AD75,0x0A56FC8C,0x12E0F818,0xCADBCBA1,
                0x2586BE56,0x952C9B46,0x07C6A43C,0x78967DF3,0x477B2E49,0x2C5D7B6D,0x8A637272,
                0x59ACBCB4,0x74A0E447,0xC1F8800F,0x35C015DC,0x230794C2,0x4405F328,0xEC2ADBA5,
                0xD832B845,0x6E4ED287,0x48E9F7A2,0xA44BE89F,0x38CBB725,0xBF6EF4E6,0xDC0E83FA,
                0x54238D12,0xF4F0C1E3,0xA60857FD,0xC43C64B9,0x00C851EF,0x33D75F36,0x5FD39866,
                0xD1EFA08A,0xA0640089,0x877A978B,0x99175D86,0x57DFACBB,0xCEB02DE9,0xCF4D5C09,
                0x3A8813D4,0xB7448816,0x63FA5568,0x06BE014B,0xD642FA7B,0x10AA7C90,0x8082C88E,
                0x1AFCBA79,0x7519549D,0x490A87FF,0x8820C3A0
            };

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            h ^= 0xFFFFFFFF;

            while( iLen-- )
            {
                h = (h >> 8) ^ crcTable[ (h ^ (*pPtr++)) & 0xFF ];
            }

            return hash( 32,  h ^ 0xFFFFFFFF );
        }

        template< typename T >
        static hash GCRC( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return GCRC( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash GCRC( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return GCRC( input, input ? strlen(input) : 0, my_hash );
        }

        // Robert Sedgwicks
        static hash RS( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            basetype b = 378551;
            basetype a = 63689;

            while( iLen-- )
            {
                h = h * a + ((basetype) (*pPtr++));
                a = a * b;
            }

            return my_hash;
        }

        template< typename T >
        static hash RS( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return RS( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash RS( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return RS( input, input ? strlen(input) : 0, my_hash );
        }

        // Justin Sobel
        static hash JS( const void *pMem, size_t iLen, hash my_hash = hash( 32, 1315423911 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h ^= ((h << 5) + ((basetype) (*pPtr++)) + (h >> 2));
            }

            return my_hash;
        }

        template< typename T >
        static hash JS( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return JS( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash JS( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return JS( input, input ? strlen(input) : 0, my_hash );
        }

        // P. J. Weinberger
        static hash PJW( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            basetype BitsInUnsignedInt = (basetype)(sizeof(basetype) * 8);
            basetype ThreeQuarters     = (basetype)((BitsInUnsignedInt  * 3) / 4);
            basetype OneEighth         = (basetype)(BitsInUnsignedInt / 8);
            basetype HighBits          = (basetype)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
            basetype test              = 0;

            while( iLen-- )
            {
                h = (h << OneEighth) + ((basetype) (*pPtr++));

                if((test = h & HighBits) != 0)
                {
                    h = (( h ^ (test >> ThreeQuarters)) & (~HighBits));
                }
            }

            return my_hash;
        }

        template< typename T >
        static hash PJW( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return PJW( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash PJW( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return PJW( input, input ? strlen(input) : 0, my_hash );
        }

        // Tweaked PJW for 32-bit
        static hash ELF( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            basetype x = 0;

            while( iLen-- )
            {
                h = (h << 4) + ((basetype) (*pPtr++));
                if((x = h & 0xF0000000L) != 0)
                {
                    h ^= (x >> 24);
                }
                h &= ~x;
            }

            return my_hash;
        }

        template< typename T >
        static hash ELF( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return ELF( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash ELF( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return ELF( input, input ? strlen(input) : 0, my_hash );
        }

        // Brian Kernighan and Dennis Ritchie
        static hash BKDR( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            const basetype seed_ = 131; // 31 131 1313 13131 131313 etc..

            while( iLen-- )
            {
                h = (h * seed_) + ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        template< typename T >
        static hash BKDR( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return BKDR( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash BKDR( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return BKDR( input, input ? strlen(input) : 0, my_hash );
        }

        // Open source SDBM project
        static hash SDBM( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h = ((basetype) (*pPtr++)) + (h << 6) + (h << 16) - h;
            }

            return my_hash;
        }

        template< typename T >
        static hash SDBM( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return SDBM( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash SDBM( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return SDBM( input, input ? strlen(input) : 0, my_hash );
        }

        // Daniel J. Bernstein
        static hash DJB( const void *pMem, size_t iLen, hash my_hash = hash( 32, 5381 ) ) //seed=0
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h = ((h << 5) + h) + ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        template< typename T >
        static hash DJB( const T &input, hash my_hash = hash( 32, 5381 ) )
        {
            return DJB( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash DJB( const char *input = (const char *)0, hash my_hash = hash( 32, 5381 ) )
        {
            return DJB( input, input ? strlen(input) : 0, my_hash );
        }

        // Daniel J. Bernstein (2)
        static hash DJB2( const void *pMem, size_t iLen, hash my_hash = hash( 32, 5381 ) ) //seed=0
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h = ((h << 5) + h) ^ ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        template< typename T >
        static hash DJB2( const T &input, hash my_hash = hash( 32, 5381 ) )
        {
            return DJB2( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash DJB2( const char *input = (const char *)0, hash my_hash = hash( 32, 5381 ) )
        {
            return DJB2( input, input ? strlen(input) : 0, my_hash );
        }

        // ?
        static hash BP( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h = h << 7 ^ ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        template< typename T >
        static hash BP( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return BP( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash BP( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return BP( input, input ? strlen(input) : 0, my_hash );
        }

        // Fowler-Noll-Vo
        static hash FNV( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            const basetype fnv_prime = 0x811C9DC5;

            while( iLen-- )
            {
                h *= fnv_prime;
                h ^= ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        template< typename T >
        static hash FNV( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return FNV( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash FNV( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return FNV( input, input ? strlen(input) : 0, my_hash );
        }

        // Arash Partow
        static hash AP( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0xAAAAAAAA ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            for( size_t i = 0; i < iLen; i++ )
            {
                h ^= ((i & 1) == 0) ? 	(  (h <<  7) ^ ((basetype) (*pPtr++)) * (h >> 3)) :
                                        (~((h << 11) + ((basetype) (*pPtr++)) ^ (h >> 5)));
            }

            return my_hash;
        }

        template< typename T >
        static hash AP( const T &input, hash my_hash = hash( 32, 0xAAAAAAAA ) )
        {
            return AP( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash AP( const char *input = (const char *)0, hash my_hash = hash( 32, 0xAAAAAAAA ) )
        {
            return AP( input, input ? strlen(input) : 0, my_hash );
        }

        // Bob Jenkins (one-at-a-time)
        static hash BJ1( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            while( iLen-- )
            {
                h += ((basetype) (*pPtr++));
                h += (h << 10);
                h ^= (h >> 6);
            }

            h += (h << 3);
            h ^= (h >> 11);
            h += (h << 15);

            return my_hash;
        }

        template< typename T >
        static hash BJ1( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return BJ1( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash BJ1( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return BJ1( input, input ? strlen(input) : 0, my_hash );
        }

        // Murmurmy_Hash2 by Austin Appleby
        static hash MH2( const void *pMem, size_t iLen, hash my_hash = hash( 32, 0 ) )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const basetype m = 0x5bd1e995;
            const int r = 24;

            basetype h = my_hash[0] ^ iLen;

            const unsigned char *data = (const unsigned char *)pMem;

            while(iLen >= 4)
            {
                basetype k;

                k  = data[0];
                k |= data[1] << 8;
                k |= data[2] << 16;
                k |= data[3] << 24;

                k *= m;
                k ^= k >> r;
                k *= m;

                h *= m;
                h ^= k;

                data += 4;
                iLen -= 4;
            }

            switch(iLen)
            {
                case 3: h ^= data[2] << 16;
                case 2: h ^= data[1] << 8;
                case 1: h ^= data[0];
                        h *= m;
            };

            h ^= h >> 13;
            h *= m;
            h ^= h >> 15;

            return hash( 32, h);
        }

        template< typename T >
        static hash MH2( const T &input, hash my_hash = hash( 32, 0 ) )
        {
            return MH2( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash MH2( const char *input = (const char *)0, hash my_hash = hash( 32, 0 ) )
        {
            return MH2( input, input ? strlen(input) : 0, my_hash );
        }

        // Mostly basetyped on Paul E. Jones' sha1 implementation
        static hash SHA1( const void *pMem, basetype iLen, hash my_hash = hash( 160, 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 ) )
        {
            // if( pMem == 0 || iLen == 0 ) return my_hash;

            struct Process
            {
                static basetype CircularShift(int bits, basetype word)
                {
                    return ((word << bits) & 0xFFFFFFFF) | ((word & 0xFFFFFFFF) >> (32-bits));
                }

                static void MessageBlock( hash &H, unsigned char *Message_Block, int &Message_Block_Index )
                {
                    const basetype K[] = {                  // Constants defined for SHA-1
                        0x5A827999,
                        0x6ED9EBA1,
                        0x8F1BBCDC,
                        0xCA62C1D6
                        };
                    int     t;                          // Loop counter
                    basetype    temp;                       // Temporary word value
                    basetype    W[80];                      // Word sequence
                    basetype    A, B, C, D, E;              // Word buffers

                    /*
                     *  Initialize the first 16 words in the array W
                     */
                    for(t = 0; t < 16; t++)
                    {
                        W[t] = ((basetype) Message_Block[t * 4]) << 24;
                        W[t] |= ((basetype) Message_Block[t * 4 + 1]) << 16;
                        W[t] |= ((basetype) Message_Block[t * 4 + 2]) << 8;
                        W[t] |= ((basetype) Message_Block[t * 4 + 3]);
                    }

                    for(t = 16; t < 80; t++)
                    {
                        W[t] = CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
                    }

                    A = H[0];
                    B = H[1];
                    C = H[2];
                    D = H[3];
                    E = H[4];

                    for(t = 0; t < 20; t++)
                    {
                        temp = CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0]; //D^(B&(C^D))
                        temp &= 0xFFFFFFFF;
                        E = D;
                        D = C;
                        C = CircularShift(30,B);
                        B = A;
                        A = temp;
                    }

                    for(t = 20; t < 40; t++)
                    {
                        temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
                        temp &= 0xFFFFFFFF;
                        E = D;
                        D = C;
                        C = CircularShift(30,B);
                        B = A;
                        A = temp;
                    }

                    for(t = 40; t < 60; t++)
                    {
                        temp = CircularShift(5,A) +
                        ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];         //(B & C) | (D & (B | C))
                        temp &= 0xFFFFFFFF;
                        E = D;
                        D = C;
                        C = CircularShift(30,B);
                        B = A;
                        A = temp;
                    }

                    for(t = 60; t < 80; t++)
                    {
                        temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
                        temp &= 0xFFFFFFFF;
                        E = D;
                        D = C;
                        C = CircularShift(30,B);
                        B = A;
                        A = temp;
                    }

                    H[0] = (H[0] + A) & 0xFFFFFFFF;
                    H[1] = (H[1] + B) & 0xFFFFFFFF;
                    H[2] = (H[2] + C) & 0xFFFFFFFF;
                    H[3] = (H[3] + D) & 0xFFFFFFFF;
                    H[4] = (H[4] + E) & 0xFFFFFFFF;

                    Message_Block_Index = 0;
                }
            };

            // 512-bit message blocks
            unsigned char Message_Block[64];
            // Index into message block array
            int Message_Block_Index = 0;
            // Message length in bits
            basetype Length_Low = 0, Length_High = 0;

            if( iLen > 0 )
            {
                // Is the message digest corrupted?
                bool Corrupted = false;

                // Input()

                unsigned char *message_array = (unsigned char *)pMem;

                while(iLen-- && !Corrupted)
                {
                    Message_Block[Message_Block_Index++] = (*message_array & 0xFF);

                    Length_Low += 8;
                    Length_Low &= 0xFFFFFFFF;               // Force it to 32 bits
                    if (Length_Low == 0)
                    {
                        Length_High++;
                        Length_High &= 0xFFFFFFFF;          // Force it to 32 bits
                        if (Length_High == 0)
                        {
                            Corrupted = true;               // Message is too long
                        }
                    }

                    if (Message_Block_Index == 64)
                    {
                        Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );
                    }

                    message_array++;
                }

                assert( !Corrupted );
            }

            // Result() and PadMessage()

            /*
            *  Check to see if the current message block is too small to hold
            *  the initial padding bits and length.  If so, we will pad the
            *  block, process it, and then continue padding into a second block.
            */
            if (Message_Block_Index > 55)
            {
                Message_Block[Message_Block_Index++] = 0x80;

                while(Message_Block_Index < 64)
                {
                    Message_Block[Message_Block_Index++] = 0;
                }

                Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );

                while(Message_Block_Index < 56)
                {
                    Message_Block[Message_Block_Index++] = 0;
                }
            }
            else
            {
                Message_Block[Message_Block_Index++] = 0x80;

                while(Message_Block_Index < 56)
                {
                    Message_Block[Message_Block_Index++] = 0;
                }
            }

            /*
             *  Store the message length as the last 8 octets
             */
            Message_Block[56] = (Length_High >> 24) & 0xFF;
            Message_Block[57] = (Length_High >> 16) & 0xFF;
            Message_Block[58] = (Length_High >> 8) & 0xFF;
            Message_Block[59] = (Length_High) & 0xFF;
            Message_Block[60] = (Length_Low >> 24) & 0xFF;
            Message_Block[61] = (Length_Low >> 16) & 0xFF;
            Message_Block[62] = (Length_Low >> 8) & 0xFF;
            Message_Block[63] = (Length_Low) & 0xFF;

            Process::MessageBlock( my_hash, Message_Block, Message_Block_Index );

            return my_hash;
        }

        template< typename T >
        static hash SHA1( const T &input, hash my_hash = hash( 160, 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 ) )
        {
            return SHA1( input.data(), input.size() * sizeof( *input.begin() ), my_hash );
        }

        static hash SHA1( const char *input = (const char *)0, hash my_hash = hash( 160, 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 ) )
        {
            return SHA1( input, input ? strlen(input) : 0, my_hash );
        }
    };
}

namespace cocoa
{
    template< typename T >
    inline hash CRC32( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::CRC32( input, my_hash );
    }
    template< typename T >
    inline hash GCRC( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::GCRC( input, my_hash );
    }
    template< typename T >
    inline hash RS( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::RS( input, my_hash );
    }
    template< typename T >
    inline hash JS( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::JS( input, my_hash );
    }
    template< typename T >
    inline hash PJW( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::PJW( input, my_hash );
    }
    template< typename T >
    inline hash ELF( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::ELF( input, my_hash );
    }
    template< typename T >
    inline hash BKDR( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::BKDR( input, my_hash );
    }
    template< typename T >
    inline hash SDBM( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::SDBM( input, my_hash );
    }
    template< typename T >
    inline hash DJB( const T &input, hash my_hash = hash( 32, 5381 ) ) {
        return hash::DJB( input, my_hash );
    }
    template< typename T >
    inline hash DJB2( const T &input, hash my_hash = hash( 32, 5381 ) ) {
        return hash::DJB2( input, my_hash );
    }
    template< typename T >
    inline hash BP( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::BP( input, my_hash );
    }
    template< typename T >
    inline hash FNV( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::FNV( input, my_hash );
    }
    template< typename T >
    inline hash AP( const T &input, hash my_hash = hash( 32, 0xAAAAAAAA ) ) {
        return hash::AP( input, my_hash );
    }
    template< typename T >
    inline hash BJ1( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::BJ1( input, my_hash );
    }
    template< typename T >
    inline hash MH2( const T &input, hash my_hash = hash( 32, 0 ) ) {
        return hash::MH2( input, my_hash );
    }
    template< typename T >
    inline hash SHA1( const T &input, hash my_hash = hash( 160, 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 ) ) {
        return hash::SHA1( input, my_hash );
    }
}

#include <iostream>

std::ostream &operator<<( std::ostream &os, const cocoa::hash &h );

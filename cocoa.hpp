/* Cocoa, an amalgamation of hashing algorithms.
 * CRC32, CRC64, GCRC, RS, JS, PJW, ELF, BKDR, SBDM, DJB, DJB2, BP, FNV, FNV1a, AP, BJ1, MH2, SHA1, SFH
 * Copyright (c) 2010,2011,2012,2013,2014 Mario 'rlyeh' Rodriguez, zlib/libpng licensed

 * This source file is based on code from Arash Partow (http://www.partow.net)
 * plus the original and credited authors for each algorithm. Thanks everybody!

 * To do:
 * - add MD5
 * - add comparison operators (>,<=,>=)
 * - add adler32 hashing
 * - add perfect hashing ( ref: http://cmph.sourceforge.net/index.html || http://burtleburtle.net/bob/hash/perfect.html )
 * - add boost hashing: seed ^= hash_value(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

 * - rlyeh
 */

#pragma once

#include <stddef.h>

#include <cassert>
#include <cstdint>
#include <cstring>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#define COCOA_VERSION "1.0.0" /* (2015/06/12) Removed warnings
#define COCOA_VERSION "0.0.0" // (2010/xx/xx) Initial commit */

namespace cocoa
{
    typedef std::uint32_t basetype;
    enum { basebits = sizeof(basetype) * 8 };

    struct use {
        using hash = std::vector<basetype>;

        enum enumeration {
            CRC32,CRC64,GCRC,RS,JS,PJW,ELF,BKDR,SDBM,DJB,DJB2,BP,FNV,FNV1a,AP,BJ1,MH2,SHA1,SFH
        };

        static
        bool is_little_endian() {
            const long endian = 1;
            return ((char*)&endian)[0] > 0;
        }

        static
        bool is_big_endian() {
            return !is_little_endian();
        }

       // CRC32
        static hash fCRC32( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

            return { ~h };
        }

        // CRC64-ECMA
        static hash fCRC64( const void *pMem, size_t iLen, hash my_hash = { 0, 0 } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            static const std::uint64_t crcTable[256] =
            {
                0x0000000000000000ULL, 0x42F0E1EBA9EA3693ULL, 0x85E1C3D753D46D26ULL, 0xC711223CFA3E5BB5ULL,
                0x493366450E42ECDFULL, 0x0BC387AEA7A8DA4CULL, 0xCCD2A5925D9681F9ULL, 0x8E224479F47CB76AULL,
                0x9266CC8A1C85D9BEULL, 0xD0962D61B56FEF2DULL, 0x17870F5D4F51B498ULL, 0x5577EEB6E6BB820BULL,
                0xDB55AACF12C73561ULL, 0x99A54B24BB2D03F2ULL, 0x5EB4691841135847ULL, 0x1C4488F3E8F96ED4ULL,
                0x663D78FF90E185EFULL, 0x24CD9914390BB37CULL, 0xE3DCBB28C335E8C9ULL, 0xA12C5AC36ADFDE5AULL,
                0x2F0E1EBA9EA36930ULL, 0x6DFEFF5137495FA3ULL, 0xAAEFDD6DCD770416ULL, 0xE81F3C86649D3285ULL,
                0xF45BB4758C645C51ULL, 0xB6AB559E258E6AC2ULL, 0x71BA77A2DFB03177ULL, 0x334A9649765A07E4ULL,
                0xBD68D2308226B08EULL, 0xFF9833DB2BCC861DULL, 0x388911E7D1F2DDA8ULL, 0x7A79F00C7818EB3BULL,
                0xCC7AF1FF21C30BDEULL, 0x8E8A101488293D4DULL, 0x499B3228721766F8ULL, 0x0B6BD3C3DBFD506BULL,
                0x854997BA2F81E701ULL, 0xC7B97651866BD192ULL, 0x00A8546D7C558A27ULL, 0x4258B586D5BFBCB4ULL,
                0x5E1C3D753D46D260ULL, 0x1CECDC9E94ACE4F3ULL, 0xDBFDFEA26E92BF46ULL, 0x990D1F49C77889D5ULL,
                0x172F5B3033043EBFULL, 0x55DFBADB9AEE082CULL, 0x92CE98E760D05399ULL, 0xD03E790CC93A650AULL,
                0xAA478900B1228E31ULL, 0xE8B768EB18C8B8A2ULL, 0x2FA64AD7E2F6E317ULL, 0x6D56AB3C4B1CD584ULL,
                0xE374EF45BF6062EEULL, 0xA1840EAE168A547DULL, 0x66952C92ECB40FC8ULL, 0x2465CD79455E395BULL,
                0x3821458AADA7578FULL, 0x7AD1A461044D611CULL, 0xBDC0865DFE733AA9ULL, 0xFF3067B657990C3AULL,
                0x711223CFA3E5BB50ULL, 0x33E2C2240A0F8DC3ULL, 0xF4F3E018F031D676ULL, 0xB60301F359DBE0E5ULL,
                0xDA050215EA6C212FULL, 0x98F5E3FE438617BCULL, 0x5FE4C1C2B9B84C09ULL, 0x1D14202910527A9AULL,
                0x93366450E42ECDF0ULL, 0xD1C685BB4DC4FB63ULL, 0x16D7A787B7FAA0D6ULL, 0x5427466C1E109645ULL,
                0x4863CE9FF6E9F891ULL, 0x0A932F745F03CE02ULL, 0xCD820D48A53D95B7ULL, 0x8F72ECA30CD7A324ULL,
                0x0150A8DAF8AB144EULL, 0x43A04931514122DDULL, 0x84B16B0DAB7F7968ULL, 0xC6418AE602954FFBULL,
                0xBC387AEA7A8DA4C0ULL, 0xFEC89B01D3679253ULL, 0x39D9B93D2959C9E6ULL, 0x7B2958D680B3FF75ULL,
                0xF50B1CAF74CF481FULL, 0xB7FBFD44DD257E8CULL, 0x70EADF78271B2539ULL, 0x321A3E938EF113AAULL,
                0x2E5EB66066087D7EULL, 0x6CAE578BCFE24BEDULL, 0xABBF75B735DC1058ULL, 0xE94F945C9C3626CBULL,
                0x676DD025684A91A1ULL, 0x259D31CEC1A0A732ULL, 0xE28C13F23B9EFC87ULL, 0xA07CF2199274CA14ULL,
                0x167FF3EACBAF2AF1ULL, 0x548F120162451C62ULL, 0x939E303D987B47D7ULL, 0xD16ED1D631917144ULL,
                0x5F4C95AFC5EDC62EULL, 0x1DBC74446C07F0BDULL, 0xDAAD56789639AB08ULL, 0x985DB7933FD39D9BULL,
                0x84193F60D72AF34FULL, 0xC6E9DE8B7EC0C5DCULL, 0x01F8FCB784FE9E69ULL, 0x43081D5C2D14A8FAULL,
                0xCD2A5925D9681F90ULL, 0x8FDAB8CE70822903ULL, 0x48CB9AF28ABC72B6ULL, 0x0A3B7B1923564425ULL,
                0x70428B155B4EAF1EULL, 0x32B26AFEF2A4998DULL, 0xF5A348C2089AC238ULL, 0xB753A929A170F4ABULL,
                0x3971ED50550C43C1ULL, 0x7B810CBBFCE67552ULL, 0xBC902E8706D82EE7ULL, 0xFE60CF6CAF321874ULL,
                0xE224479F47CB76A0ULL, 0xA0D4A674EE214033ULL, 0x67C58448141F1B86ULL, 0x253565A3BDF52D15ULL,
                0xAB1721DA49899A7FULL, 0xE9E7C031E063ACECULL, 0x2EF6E20D1A5DF759ULL, 0x6C0603E6B3B7C1CAULL,
                0xF6FAE5C07D3274CDULL, 0xB40A042BD4D8425EULL, 0x731B26172EE619EBULL, 0x31EBC7FC870C2F78ULL,
                0xBFC9838573709812ULL, 0xFD39626EDA9AAE81ULL, 0x3A28405220A4F534ULL, 0x78D8A1B9894EC3A7ULL,
                0x649C294A61B7AD73ULL, 0x266CC8A1C85D9BE0ULL, 0xE17DEA9D3263C055ULL, 0xA38D0B769B89F6C6ULL,
                0x2DAF4F0F6FF541ACULL, 0x6F5FAEE4C61F773FULL, 0xA84E8CD83C212C8AULL, 0xEABE6D3395CB1A19ULL,
                0x90C79D3FEDD3F122ULL, 0xD2377CD44439C7B1ULL, 0x15265EE8BE079C04ULL, 0x57D6BF0317EDAA97ULL,
                0xD9F4FB7AE3911DFDULL, 0x9B041A914A7B2B6EULL, 0x5C1538ADB04570DBULL, 0x1EE5D94619AF4648ULL,
                0x02A151B5F156289CULL, 0x4051B05E58BC1E0FULL, 0x87409262A28245BAULL, 0xC5B073890B687329ULL,
                0x4B9237F0FF14C443ULL, 0x0962D61B56FEF2D0ULL, 0xCE73F427ACC0A965ULL, 0x8C8315CC052A9FF6ULL,
                0x3A80143F5CF17F13ULL, 0x7870F5D4F51B4980ULL, 0xBF61D7E80F251235ULL, 0xFD913603A6CF24A6ULL,
                0x73B3727A52B393CCULL, 0x31439391FB59A55FULL, 0xF652B1AD0167FEEAULL, 0xB4A25046A88DC879ULL,
                0xA8E6D8B54074A6ADULL, 0xEA16395EE99E903EULL, 0x2D071B6213A0CB8BULL, 0x6FF7FA89BA4AFD18ULL,
                0xE1D5BEF04E364A72ULL, 0xA3255F1BE7DC7CE1ULL, 0x64347D271DE22754ULL, 0x26C49CCCB40811C7ULL,
                0x5CBD6CC0CC10FAFCULL, 0x1E4D8D2B65FACC6FULL, 0xD95CAF179FC497DAULL, 0x9BAC4EFC362EA149ULL,
                0x158E0A85C2521623ULL, 0x577EEB6E6BB820B0ULL, 0x906FC95291867B05ULL, 0xD29F28B9386C4D96ULL,
                0xCEDBA04AD0952342ULL, 0x8C2B41A1797F15D1ULL, 0x4B3A639D83414E64ULL, 0x09CA82762AAB78F7ULL,
                0x87E8C60FDED7CF9DULL, 0xC51827E4773DF90EULL, 0x020905D88D03A2BBULL, 0x40F9E43324E99428ULL,
                0x2CFFE7D5975E55E2ULL, 0x6E0F063E3EB46371ULL, 0xA91E2402C48A38C4ULL, 0xEBEEC5E96D600E57ULL,
                0x65CC8190991CB93DULL, 0x273C607B30F68FAEULL, 0xE02D4247CAC8D41BULL, 0xA2DDA3AC6322E288ULL,
                0xBE992B5F8BDB8C5CULL, 0xFC69CAB42231BACFULL, 0x3B78E888D80FE17AULL, 0x7988096371E5D7E9ULL,
                0xF7AA4D1A85996083ULL, 0xB55AACF12C735610ULL, 0x724B8ECDD64D0DA5ULL, 0x30BB6F267FA73B36ULL,
                0x4AC29F2A07BFD00DULL, 0x08327EC1AE55E69EULL, 0xCF235CFD546BBD2BULL, 0x8DD3BD16FD818BB8ULL,
                0x03F1F96F09FD3CD2ULL, 0x41011884A0170A41ULL, 0x86103AB85A2951F4ULL, 0xC4E0DB53F3C36767ULL,
                0xD8A453A01B3A09B3ULL, 0x9A54B24BB2D03F20ULL, 0x5D45907748EE6495ULL, 0x1FB5719CE1045206ULL,
                0x919735E51578E56CULL, 0xD367D40EBC92D3FFULL, 0x1476F63246AC884AULL, 0x568617D9EF46BED9ULL,
                0xE085162AB69D5E3CULL, 0xA275F7C11F7768AFULL, 0x6564D5FDE549331AULL, 0x279434164CA30589ULL,
                0xA9B6706FB8DFB2E3ULL, 0xEB46918411358470ULL, 0x2C57B3B8EB0BDFC5ULL, 0x6EA7525342E1E956ULL,
                0x72E3DAA0AA188782ULL, 0x30133B4B03F2B111ULL, 0xF7021977F9CCEAA4ULL, 0xB5F2F89C5026DC37ULL,
                0x3BD0BCE5A45A6B5DULL, 0x79205D0E0DB05DCEULL, 0xBE317F32F78E067BULL, 0xFCC19ED95E6430E8ULL,
                0x86B86ED5267CDBD3ULL, 0xC4488F3E8F96ED40ULL, 0x0359AD0275A8B6F5ULL, 0x41A94CE9DC428066ULL,
                0xCF8B0890283E370CULL, 0x8D7BE97B81D4019FULL, 0x4A6ACB477BEA5A2AULL, 0x089A2AACD2006CB9ULL,
                0x14DEA25F3AF9026DULL, 0x562E43B4931334FEULL, 0x913F6188692D6F4BULL, 0xD3CF8063C0C759D8ULL,
                0x5DEDC41A34BBEEB2ULL, 0x1F1D25F19D51D821ULL, 0xD80C07CD676F8394ULL, 0x9AFCE626CE85B507ULL,
            };

            const unsigned char *pPtr = (const unsigned char *)pMem;

            std::uint64_t h;

            if( is_little_endian() )
                { h = my_hash[0] & 0xFFFFFFFF; h = ( (h << 32) | (my_hash[1] & 0xFFFFFFFF) ); }
            else
                { h = my_hash[1] & 0xFFFFFFFF; h = ( (h << 32) | (my_hash[0] & 0xFFFFFFFF) ); }

            h = ~h;

            while( iLen-- )
            {
                h = crcTable[ ( (h >> 56) ^ (*pPtr++) ) & 0xff ] ^ (h << 8);
            }

            h = ~h;

            if( is_little_endian() )
                return { basetype( ( h >> 32 ) & 0xFFFFFFFF ), basetype( h & 0xFFFFFFFF ) };
            else
                return { basetype( h & 0xFFFFFFFF ), basetype( ( h >> 32 ) & 0xFFFFFFFF ) };
        }

        // Generalized CRC (less collisions), Bob Jenkins
        static hash fGCRC( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

            return { h ^ 0xFFFFFFFF };
        }

        // Robert Sedgwicks
        static hash fRS( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Justin Sobel
        static hash fJS( const void *pMem, size_t iLen, hash my_hash = { 1315423911 } )
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

        // P. J. Weinberger
        static hash fPJW( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Tweaked PJW for 32-bit
        static hash fELF( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Brian Kernighan and Dennis Ritchie
        static hash fBKDR( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Open source SDBM project
        static hash fSDBM( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Daniel J. Bernstein
        static hash fDJB( const void *pMem, size_t iLen, hash my_hash = { 5381 } ) //seed=0
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

        // Daniel J. Bernstein (2)
        static hash fDJB2( const void *pMem, size_t iLen, hash my_hash = { 5381 } ) //seed=0
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

        // ?
        static hash fBP( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Fowler-Noll-Vo
        static hash fFNV( const void *pMem, size_t iLen, hash my_hash = { 0x811C9DC5 } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            const basetype fnv_prime = 0x1000193;

            while( iLen-- )
            {
                h *= fnv_prime;
                h ^= ((basetype) (*pPtr++));
            }

            return my_hash;
        }

        // Fowler-Noll-Vo-1a
        static hash fFNV1a( const void *pMem, size_t iLen, hash my_hash = { 0x811C9DC5 } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            const basetype fnv_prime = 0x1000193;

            while( iLen-- )
            {
                h ^= ((basetype) (*pPtr++));
                h *= fnv_prime;
            }

            return my_hash;
        }

        // Arash Partow
        static hash fAP( const void *pMem, size_t iLen, hash my_hash = { 0xAAAAAAAA } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const unsigned char *pPtr = (const unsigned char *)pMem;
            basetype &h = my_hash[0];

            for( size_t i = 0; i < iLen; i++ )
            {
                h ^= ((i & 1) == 0) ?   (  (h <<  7) ^ ((basetype) (*pPtr++)) * (h >> 3)) :
                                        (~((h << 11) + ((basetype) (*pPtr++)) ^ (h >> 5)));
            }

            return my_hash;
        }

        // Bob Jenkins (one-at-a-time)
        static hash fBJ1( const void *pMem, size_t iLen, hash my_hash = { 0 } )
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

        // Murmurmy_Hash2 by Austin Appleby
        static hash fMH2( const void *pMem, size_t iLen, hash my_hash = { 0 } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

            const basetype m = 0x5bd1e995;
            const int r = 24;

            basetype h = my_hash[0] ^ ((basetype)iLen);

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

            return { h };
        }

        // SuperFastHash by Paul Hsieh
        static hash fSFH( const void *pMem, size_t iLen, hash my_hash = hash { 0 } )
        {
            if( pMem == 0 || iLen == 0 ) return my_hash;

#           undef get16bits
#           if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
                    || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#               define get16bits(d) (*((const uint16_t *) (d)))
#           else
#               define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#           endif

            std::uint32_t tmp;
            int rem;

            rem = iLen & 3;
            iLen >>= 2;

            const char * data = (const char *)pMem;
            basetype &h = my_hash[0];

            /* Main loop */
            for (;iLen > 0; iLen--) {
                   h += get16bits (data);
                 tmp  = (get16bits (data+2) << 11) ^ h;
                   h  = (h << 16) ^ tmp;
                data += 2*sizeof (uint16_t);
                   h += h >> 11;
            }

            /* Handle end cases */
            switch (rem) { default:
                case 3: h += get16bits (data);
                        h ^= h << 16;
                        h ^= ((signed char)data[sizeof (uint16_t)]) << 18;
                        h += h >> 11;
                        break;
                case 2: h += get16bits (data);
                        h ^= h << 11;
                        h += h >> 17;
                        break;
                case 1: h += (signed char)*data;
                        h ^= h << 10;
                        h += h >> 1;
            }

            /* Force "avalanching" of final 127 bits */
            h ^= h << 3;
            h += h >> 5;
            h ^= h << 4;
            h += h >> 17;
            h ^= h << 25;
            h += h >> 6;

            return { h };

#           undef get16bits
        }

        // Mostly based on Paul E. Jones' sha1 implementation
        static hash fSHA1( const void *pMem, size_t iLen, hash my_hash = hash{ 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0 } )
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

        // general interface

        static hash any( int FN, hash &h, const void *ptr, size_t len ) {
            /**/ if( FN == use::CRC32 ) return h = cocoa::use::fCRC32(ptr, len, h);
            else if( FN == use::CRC64 ) return h = cocoa::use::fCRC64(ptr, len, h);
            else if( FN == use::GCRC  ) return h = cocoa::use::fGCRC(ptr, len, h);
            else if( FN == use::RS    ) return h = cocoa::use::fRS(ptr, len, h);
            else if( FN == use::JS    ) return h = cocoa::use::fJS(ptr, len, h);
            else if( FN == use::PJW   ) return h = cocoa::use::fPJW(ptr, len, h);
            else if( FN == use::ELF   ) return h = cocoa::use::fELF(ptr, len, h);
            else if( FN == use::BKDR  ) return h = cocoa::use::fBKDR(ptr, len, h);
            else if( FN == use::SDBM  ) return h = cocoa::use::fSDBM(ptr, len, h);
            else if( FN == use::DJB   ) return h = cocoa::use::fDJB(ptr, len, h);
            else if( FN == use::DJB2  ) return h = cocoa::use::fDJB2(ptr, len, h);
            else if( FN == use::BP    ) return h = cocoa::use::fBP(ptr, len, h);
            else if( FN == use::FNV   ) return h = cocoa::use::fFNV(ptr, len, h);
            else if( FN == use::FNV1a ) return h = cocoa::use::fFNV1a(ptr, len, h);
            else if( FN == use::AP    ) return h = cocoa::use::fAP(ptr, len, h);
            else if( FN == use::BJ1   ) return h = cocoa::use::fBJ1(ptr, len, h);
            else if( FN == use::MH2   ) return h = cocoa::use::fMH2(ptr, len, h);
            else if( FN == use::SHA1  ) return h = cocoa::use::fSHA1(ptr, len, h);
            else if( FN == use::SFH   ) return h = cocoa::use::fSFH(ptr, len, h);
            return h;
        }
    };

    template<int FN>
    class hash
    {
        std::vector<basetype> h;

        public:

        hash() : h( 1, 0 ) {
            /**/ if( FN == cocoa::use::DJB) h[0] = 5381;
            else if( FN == cocoa::use::DJB2) h[0] = 5381;
            else if( FN == cocoa::use::FNV) h[0] = 0x811C9DC5;
            else if( FN == cocoa::use::FNV1a) h[0] = 0x811C9DC5;
            else if( FN == cocoa::use::AP) h[0] = 0xAAAAAAAA;
            else if( FN == cocoa::use::CRC64) h = { 0, 0 };
            else if( FN == cocoa::use::SHA1) h = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        }

        inline basetype &operator []( basetype i )
        {
            return h[i];
        }
        inline const basetype &operator []( basetype i ) const
        {
            return h[i];
        }

        inline bool operator ==( const hash &t ) const
        {
            return h == t.h;
        }

        inline bool operator !=( const hash &t ) const
        {
            return h != t.h;
        }

        inline bool operator<( const hash &t ) const
        {
            return h < t.h;
        }

        inline bool operator ==( const std::string &t ) const
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

            if( use::is_big_endian() )
                for( std::vector<basetype>::const_iterator it = h.begin(); it != h.end(); ++it )
                    for( unsigned i = 0; i < sizeof(basetype); ++i )
                        blob.push_back( ( (*it) >> (i * 8) ) & 0xff );
            else
                for( std::vector<basetype>::const_iterator it = h.begin(); it != h.end(); ++it )
                    for( unsigned i = sizeof(basetype); i-- > 0; )
                        blob.push_back( ( (*it) >> (i * 8) ) & 0xff );

            return blob;
        }

        public:

        // ostream

        template<typename ostream>
        inline friend ostream &operator<<( ostream &os, const hash &self )
        {
            return (os << self.str()), os;
        }

        // chain hasher

        template<typename T>
        hash operator()( const T &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, input.data(), input.size() * sizeof( *input.begin() ) ), self;
        }

        hash operator()( const char *input = (const char *)0 ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, input, input ? std::strlen(input) : 0 ), self;
        }
        hash operator()( const char &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, &input, sizeof(input) ), self;
        }
        hash operator()( const int &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, &input, sizeof(input) ), self;
        }
        hash operator()( const size_t &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, &input, sizeof(input) ), self;
        }
        hash operator()( const float &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, &input, sizeof(input) ), self;
        }
        hash operator()( const double &input ) const {
            hash self = *this;
            return self.h = use::any( FN, self.h, &input, sizeof(input) ), self;
        }

        template<typename T, typename... Args>
        hash operator()(const T &value, Args... args) const {
            hash self = *this;
            self.operator()( value );
            self.operator()(args...);
            return self;
        }

    };
}

namespace cocoa
{
    template< typename T >
    inline hash<cocoa::use::CRC32> CRC32( const T &input, const hash<cocoa::use::CRC32> &my_hash = hash<cocoa::use::CRC32>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::CRC64> CRC64( const T &input, const hash<cocoa::use::CRC64> &my_hash = hash<cocoa::use::CRC64>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::GCRC> GCRC( const T &input, const hash<cocoa::use::GCRC> &my_hash = hash<cocoa::use::GCRC>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::RS> RS( const T &input, const hash<cocoa::use::RS> &my_hash = hash<cocoa::use::RS>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::JS> JS( const T &input, const hash<cocoa::use::JS> &my_hash = hash<cocoa::use::JS>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::PJW> PJW( const T &input, const hash<cocoa::use::PJW> &my_hash = hash<cocoa::use::PJW>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::ELF> ELF( const T &input, const hash<cocoa::use::ELF> &my_hash = hash<cocoa::use::ELF>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::BKDR> BKDR( const T &input, const hash<cocoa::use::BKDR> &my_hash = hash<cocoa::use::BKDR>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::SDBM> SDBM( const T &input, const hash<cocoa::use::SDBM> &my_hash = hash<cocoa::use::SDBM>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::DJB> DJB( const T &input, const hash<cocoa::use::DJB> &my_hash = hash<cocoa::use::DJB>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::DJB2> DJB2( const T &input, const hash<cocoa::use::DJB2> &my_hash = hash<cocoa::use::DJB2>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::BP> BP( const T &input, const hash<cocoa::use::BP> &my_hash = hash<cocoa::use::BP>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::FNV> FNV( const T &input, const hash<cocoa::use::FNV> &my_hash = hash<cocoa::use::FNV>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::FNV1a> FNV1a( const T &input, const hash<cocoa::use::FNV1a> &my_hash = hash<cocoa::use::FNV1a>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::AP> AP( const T &input, const hash<cocoa::use::AP> &my_hash = hash<cocoa::use::AP>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::BJ1> BJ1( const T &input, const hash<cocoa::use::BJ1> &my_hash = hash<cocoa::use::BJ1>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::MH2> MH2( const T &input, const hash<cocoa::use::MH2> &my_hash = hash<cocoa::use::MH2>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::SHA1> SHA1( const T &input, const hash<cocoa::use::SHA1> &my_hash = hash<cocoa::use::SHA1>() ) {
        return my_hash.operator()( input );
    }
    template< typename T >
    inline hash<cocoa::use::SFH> SFH( const T &input, const hash<cocoa::use::SFH> &my_hash = hash<cocoa::use::SFH>() ) {
        return my_hash.operator()( input );
    }
}

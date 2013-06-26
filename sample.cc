#include <cassert>

#include <iostream>
#include <string>

#include "cocoa.hpp"

int main( int argc, const char **argv )
{
    std::string key = "abcdefghijklmnopqrstuvwxyz1234567890";

    std::cout << "General Purpose Hash Function Algorithms Test" << std::endl;
    std::cout << " 1. RS-Hash Function Value:    " << cocoa::RS( key )    << std::endl;
    std::cout << " 2. JS-Hash Function Value:    " << cocoa::JS( key )    << std::endl;
    std::cout << " 3. PJW-Hash Function Value:   " << cocoa::PJW( key )   << std::endl;
    std::cout << " 4. ELF-Hash Function Value:   " << cocoa::ELF( key )   << std::endl;
    std::cout << " 5. BKDR-Hash Function Value:  " << cocoa::BKDR( key )  << std::endl;
    std::cout << " 6. SDBM-Hash Function Value:  " << cocoa::SDBM( key )  << std::endl;
    std::cout << " 7. DJB-Hash Function Value:   " << cocoa::DJB( key )   << std::endl;
    std::cout << " 8. FNV-Hash Function Value:   " << cocoa::FNV( key )   << std::endl;
    std::cout << " 9. BP-Hash Function Value:    " << cocoa::BP( key )    << std::endl;
    std::cout << "10. AP-Hash Function Value:    " << cocoa::AP( key )    << std::endl;
    std::cout << "11. CRC32-Hash Function Value: " << cocoa::CRC32( key ) << std::endl;
    std::cout << "12. CRC64-Hash Function Value: " << cocoa::CRC64( key ) << std::endl;
    std::cout << "13. MH2-Hash Function Value:   " << cocoa::MH2( key )   << std::endl;
    std::cout << "14. BJ1-Hash Function Value:   " << cocoa::BJ1( key )   << std::endl;
    std::cout << "15. CRC-Hash Function Value:   " << cocoa::GCRC( key )  << std::endl;
    std::cout << "16. SHA1-Hash Function Value:  " << cocoa::SHA1( key )  << std::endl;

    // a few tests from http://www.nitrxgen.net/hashgen/ (thanks guys!)
    assert( cocoa::CRC32("hello world").blob().size() == 4 );
    assert( cocoa::CRC32("hello world") == "0d4a1185" );
    assert( cocoa::CRC32("world", cocoa::CRC32("hello ")) == "0d4a1185" );
    assert( cocoa::CRC32("hello world") == cocoa::CRC32("hello world") );

    assert( cocoa::CRC64("hello world").blob().size() == 8 );
    assert( cocoa::CRC64("hello world") == "c287020321943b9d" );
    assert( cocoa::CRC64("world", cocoa::CRC64("hello ")) == "c287020321943b9d" );
    assert( cocoa::CRC64("hello world") == cocoa::CRC64("hello world") );

    assert( cocoa::SHA1("hello world").blob().size() == 20 );
    assert( cocoa::SHA1("hello world") == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" );
    //@todo: fixme (terminator issue). will help MD5 too
    //assert( cocoa::SHA1("world", cocoa::SHA1("hello ")) == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" );
    assert( cocoa::SHA1("hello world") == cocoa::SHA1("hello world") );

    assert( cocoa::SHA1("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709" );
    assert( cocoa::CRC32("") == "00000000" );
    assert( cocoa::CRC64("") == "0000000000000000" );

    std::cout << "All ok." << std::endl;

    return 0;
}

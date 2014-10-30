#include <cassert>
#include <string>
#include <iostream>
#include "cocoa.hpp"

int main() {
    std::string hash = cocoa::SHA1("hello world");
    std::cout << hash << std::endl;
    assert( cocoa::SHA1("hello world") == cocoa::SHA1("hello world") );
    return 0;
}

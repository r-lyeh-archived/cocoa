cocoa <a href="https://travis-ci.org/r-lyeh/cocoa"><img src="https://api.travis-ci.org/r-lyeh/cocoa.svg?branch=master" align="right" /></a>
=====

- Cocoa is an uniform hashing library written in C++11.
- Cocoa provides interface for CRC32, CRC64, GCRC, RS, JS, PJW, ELF, BKDR, SBDM, DJB, DJB2, BP, FNV, FNV1a, AP, BJ1, MH2, SHA1, SFH.
- Cocoa is tiny. Header-only.
- Cocoa is cross-platform. No dependencies.
- Cocoa is BOOST licensed.

### cocoa::hash() api
- @todocument

### Sample
```c++
#include <cassert>
#include <string>
#include "cocoa.hpp"

int main() {
    std::string hash = cocoa::SHA1("hello world");
    std::cout << hash << std::endl;
    assert( cocoa::SHA1("hello world") == cocoa::SHA1("hello world") );
    return 0;
}
```

### possible output
---------------
<pre>
~/cocoa>./test
2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
~/cocoa>
</pre>

### c++03
Check old [c++03 version here](https://github.com/r-lyeh/cocoa/tree/c70a878eae074f73ae7f5222503538c130fd6a0d)

### api
For more details check the [tests.cxx](tests.cxx) file.

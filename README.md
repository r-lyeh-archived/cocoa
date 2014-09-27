cocoa
=====

- Cocoa is an uniform hashing library written in C++.
- Provides interface for CRC32, CRC64, GCRC, RS, JS, PJW, ELF, BKDR, SBDM, DJB, DJB2, BP, FNV, FNV1a, AP, BJ1, MH2, SHA1, SFH.
- Tiny. Header-only.
- Cross-platform.
- No dependencies.
- BOOST licensed.

cocoa::hash()
-------------

- @todocument

Sample
------
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

Possible output
---------------
<pre>
~/cocoa>./test
dea3c171abcdfb3e8380d6860630f618eb6e074f
~/cocoa>
</pre>

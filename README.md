cocoa
=====

- Cocoa is an uniform hashing library written in C++.
- Provides interface for CRC32, GCRC, RS, JS, PJW, ELF, BKDR, SBDM, DJB, DJB2, BP, FNV, AP, BJ1, MH2, SHA1.
- Cross-platform. No extra dependencies.
- Requires no dependencies.
- MIT licensed.

cocoa::hash()
-------------

- @todocument

Sample
------
<pre>
#include &lt;cassert&gt;
#include &lt;string&gt;
#include "cocoa.hpp"

int main() {
    std::string hash = cocoa::SHA1("hello world");
    std::cout &lt;&lt; hash &lt;&lt; std::endl;
    assert( cocoa::SHA1("hello world") == cocoa::SHA1("hello world") );
    return 0;
}
</pre>

Possible output
---------------
<pre>
~/cocoa>./test
dea3c171abcdfb3e8380d6860630f618eb6e074f
~/cocoa>
</pre>

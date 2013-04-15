#include "cocoa.hpp"

std::ostream &operator<<( std::ostream &os, const cocoa::hash &h )
{
    return os << h.str(), os;
}

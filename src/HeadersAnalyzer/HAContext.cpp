// HAContext.cpp

#include "HAContext.hpp"

using namespace std;

ClassExportList::const_iterator
HAContext::findClassMethod(const std::string &Name) {
  if (Name[0] != '+' && Name[0] != '-')
    return iOSClasses.end();
  if (Name[1] != '[')
    return iOSClasses.end();

  // Find the first space.
  size_t SpaceIdx = Name.find(' ', 2);
  if (SpaceIdx == string::npos)
    return iOSClasses.end();

  // From `[` to the first space is a class name.
  string ClassName = Name.substr(2, SpaceIdx - 2);

  // On Mach systems, names are mangled with leading underscore.
  return iOSClasses.find('_' + ClassName);
}

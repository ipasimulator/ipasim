// HAContext.cpp

#include "HAContext.hpp"

#include "Config.hpp"
#include "ErrorReporting.hpp"

using namespace std;

ClassExportList::const_iterator HAContext::findClassMethod(const string &Name) {
  if (iOSClasses.empty())
    return iOSClasses.end();

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

bool HAContext::isInteresting(const string &Name, ExportList::iterator &Exp) {
  Exp = iOSExps.find(Name);
  if (Exp == iOSExps.end()) {
    // If not found among exported functions, try if it isn't an Objective-C
    // function.
    auto Class = findClassMethod(Name);
    if (Class != iOSClasses.end()) {
      Exp = iOSExps.insert(ExportEntry(Name)).first;
      Exp->ObjCMethod = true;
      iOSLibs[Class->second].Exports.push_back(&*Exp);
    } else {
      if constexpr (WarnUninterestingFunctions & LibType::Dylib) {
        reportWarning("found uninteresting function in Dylib (" + Name +
                      "), that's interesting");
      }
      return false;
    }
  }
  return true;
}

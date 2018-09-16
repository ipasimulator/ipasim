// HAContext.cpp

#include "HAContext.hpp"

#include "Config.hpp"
#include "ErrorReporting.hpp"

#include <llvm/ADT/Twine.h>

using namespace std;
using namespace llvm;

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

constexpr static const char *toString(LibType LibTy) {
  switch (LibTy) {
  case LibType::DLL:
    return "DLL";
  case LibType::Dylib:
    return "Dylib";
  default:
    reportFatalError("invalid `LibType`");
  }
}
template <LibType LibTy> static void warnUninteresting(const string &Name) {
  if constexpr (WarnUninterestingFunctions & LibTy) {
    constexpr const char *LibStr = toString(LibTy);
    reportWarning(Twine("found uninteresting function in ") + LibStr + " (" +
                  Name + "), that's interesting");
  }
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
      warnUninteresting<LibType::Dylib>(Name);
      return false;
    }
  }
  return true;
}
bool HAContext::isInterestingForWindows(const string &Name,
                                        ExportList::iterator &Exp,
                                        bool IgnoreDuplicates) {
  Exp = iOSExps.find(Name);
  if (Exp == iOSExps.end()) {
    warnUninteresting<LibType::DLL>(Name);
    return false;
  }
  if (Exp->Status == ExportStatus::FoundInDLL) {
    if (!IgnoreDuplicates)
      reportError(Twine("found duplicate DLL export (") + Name + ")");
    return false;
  }
  if (Exp->Status != ExportStatus::Found) {
    warnUninteresting<LibType::DLL>(Name);
    return false;
  }
  return true;
}

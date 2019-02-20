// HAContext.cpp

#include "HAContext.hpp"

#include "Common.hpp"
#include "Config.hpp"
#include "ErrorReporting.hpp"

#include <llvm/ADT/Twine.h>

using namespace std;
using namespace llvm;

bool HAContext::isClassMethod(const string &Name) {
  return (Name[0] == '+' || Name[0] == '-') && Name[1] == '[';
}
ClassExportPtr HAContext::findClassMethod(const string &Name) {
  if (iOSClasses.empty() || !isClassMethod(Name))
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

bool HAContext::isInteresting(const string &Name, ExportPtr &Exp) {
  Exp = iOSExps.find(Name);
  if (Exp == iOSExps.end()) {
    // If not found among exported functions, try if it isn't an Objective-C
    // function.
    // TODO: If it is, though, don't really export it by name from the Dylib.
    auto Class = findClassMethod(Name);
    if (Class != iOSClasses.end()) {
      Exp = iOSExps.insert(ExportEntry(Name)).first;
      Exp->ObjCMethod = true;
      std::for_each(Class->Dylibs.begin(), Class->Dylibs.end(),
                    [&Exp](auto &Dylib) { Dylib->Exports.push_back(Exp); });
    } else {
      warnUninteresting<LibType::Dylib>(Name);
      return false;
    }
  }
  return true;
}
bool HAContext::isInterestingForWindows(const string &Name, ExportPtr &Exp,
                                        uint32_t RVA, bool IgnoreDuplicates) {
  Exp = iOSExps.find(Name);
  if (Exp == iOSExps.end()) {
    warnUninteresting<LibType::DLL>(Name);
    return false;
  }
  if (Exp->Status == ExportStatus::FoundInDLL) {
    // It's not an error if we find multiple symbols for the exactly same
    // function (i.e., symbols have the same RVA).
    if (!IgnoreDuplicates && Exp->RVA != RVA)
      reportError(Twine("found duplicate DLL export (") + Name + ")");
    return false;
  }
  return true;
}

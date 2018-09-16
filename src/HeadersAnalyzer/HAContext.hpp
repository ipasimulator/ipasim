// HAContext.hpp

#ifndef HACONTEXT_HPP
#define HACONTEXT_HPP

#include <llvm/IR/DerivedTypes.h>

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

struct ExportEntry;

struct DLLEntry {
  DLLEntry(std::string Name) : Name(Name), ReferenceFunc(nullptr) {}

  std::string Name;
  std::vector<const ExportEntry *> Exports;
  const ExportEntry *ReferenceFunc;
};

struct DLLGroup {
  std::filesystem::path Dir;
  std::vector<DLLEntry> DLLs;
};

enum class ExportStatus { NotFound = 0, Found, Overloaded, FoundInDLL };

struct ExportEntry {
  ExportEntry(std::string Name)
      : Name(Name), Status(ExportStatus::NotFound), RVA(0), Type(nullptr),
        ObjCMethod(false), DLLGroup(nullptr), DLL(nullptr) {}

  std::string Name;
  mutable ExportStatus Status;
  mutable uint32_t RVA;
  // This is usually empty (indicating that `to_string(RVA)` should be used
  // instead), but not for Objective-C messengers (e.g., `objc_msgSend`). There
  // it's equal to the corresponding lookup function's RVA, so that that gets
  // called instead.
  mutable std::string WrapperRVA;
  mutable llvm::FunctionType *Type;
  mutable bool ObjCMethod;
  mutable const DLLGroup *DLLGroup;
  mutable const DLLEntry *DLL;

  bool operator<(const ExportEntry &Other) const { return Name < Other.Name; }
};

using ExportList = std::set<ExportEntry>;

using ClassExportList = std::map<std::string, size_t>;

struct Dylib {
  std::string Name;
  std::vector<const ExportEntry *> Exports;
};

class HAContext {
private:
  const ExportEntry *addExp(std::string Name) {
    return &*iOSExps.insert(ExportEntry(Name)).first;
  };

public:
  ExportList iOSExps;
  std::vector<Dylib> iOSLibs = {
      {"/usr/lib/libobjc.A.dylib",
       {addExp("_sel_registerName"), addExp("_object_setIvar"),
        addExp("_objc_msgSend")}}};
  ClassExportList iOSClasses = {{"_NSObject", 0}};
  std::vector<DLLGroup> DLLGroups = {
      {"./src/objc/Debug/", {DLLEntry("libobjc.A.dll")}}};

  // This is an inverse of `CGObjCCommonMac::GetNameForMethod`.
  // TODO: Find out whether there aren't any Objective-C method name parsers
  // somewhere in the LLVM ecosystem already.
  ClassExportList::const_iterator findClassMethod(const std::string &Name);
  bool isInteresting(const std::string &Name, ExportList::iterator &Exp);
  bool isInterestingForWindows(const std::string &Name,
                               ExportList::iterator &Exp,
                               bool IgnoreDuplicates = false);
};

// !defined(HACONTEXT_HPP)
#endif

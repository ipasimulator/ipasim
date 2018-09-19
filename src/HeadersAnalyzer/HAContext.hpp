// HAContext.hpp

#ifndef HACONTEXT_HPP
#define HACONTEXT_HPP

#include "Common.hpp"

#include <llvm/IR/DerivedTypes.h>

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

template <typename T> class ContainerPtr {
public:
  using VTy = typename T::iterator;

  ContainerPtr() : Valid(false) {}
  ContainerPtr(const VTy &Value) : Valid(true), Value(Value) {}
  ContainerPtr(VTy &&Value) : Valid(true), Value(std::move(Value)) {}

  operator VTy() const { return Value; }
  auto operator*() const { return Value.operator*(); }
  auto operator-> () const { return Value.operator->(); }
  operator bool() const { return Valid; }
  bool operator==(const ContainerPtr &Other) const {
    return Value == Other.Value;
  }
  bool operator!=(const ContainerPtr &Other) const {
    return Value != Other.Value;
  }

private:
  bool Valid;
  VTy Value;
};

struct DLLEntry;
struct DLLGroup;
struct ExportEntry;
struct Dylib;

// We use `list`s instead of `vector`s, so that it's guaranteed that pointers
// (or iterators) to their items are always valid.
// TODO: Maybe use `vector`s of `unique_ptr`s instead. And then use normal
// pointers instead of `ContainerPtr` since they are guaranteed to be valid...
using DylibList = std::list<Dylib>;
using DylibPtr = ContainerPtr<DylibList>;
using ExportList = std::set<ExportEntry>;
using ExportPtr = ContainerPtr<ExportList>;
using ClassExportList = std::map<std::string, DylibPtr>;
using ClassExportPtr = ContainerPtr<ClassExportList>;
using GroupList = std::list<DLLGroup>;
using GroupPtr = ContainerPtr<GroupList>;
using DLLEntryList = std::list<DLLEntry>;
using DLLPtr = ContainerPtr<DLLEntryList>;

struct DLLEntry {
  DLLEntry(std::string Name) : Name(Name) {}

  std::string Name;
  std::vector<ExportPtr> Exports;
  ExportPtr ReferenceFunc;
};

struct DLLGroup {
  std::filesystem::path Dir;
  DLLEntryList DLLs;
};

enum class ExportStatus { NotFound = 0, Found, Overloaded, FoundInDLL };

struct ExportEntry {
  ExportEntry(std::string Name)
      : Name(Name), Status(ExportStatus::NotFound), RVA(0), Type(nullptr),
        ObjCMethod(false), Messenger(false), Stret(false) {}

  std::string Name;
  mutable ExportStatus Status;
  mutable uint32_t RVA;
  mutable llvm::FunctionType *Type;
  mutable bool ObjCMethod : 1;
  mutable bool Messenger : 1;
  mutable bool Stret : 1;
  mutable GroupPtr DLLGroup;
  mutable DLLPtr DLL;

  bool operator<(const ExportEntry &Other) const { return Name < Other.Name; }
  bool isTrivial() const {
    return !Type->getNumParams() && Type->getReturnType()->isVoidTy();
  }
};

struct Dylib {
  std::string Name;
  std::vector<ExportPtr> Exports;
};

class HAContext {
public:
  ExportList iOSExps;
  DylibList iOSLibs;
  ClassExportList iOSClasses;
  GroupList DLLGroups = {{"./src/objc/Debug/", {DLLEntry("libobjc.A.dll")}},
                         {"./deps/WinObjC/build/Win32/Debug/Universal Windows/",
                          {DLLEntry("Foundation.dll")}}};

  static constexpr const char *MsgSendPrefix = "_objc_msgSend";
  static constexpr size_t MsgSendLength = length(MsgSendPrefix);
  static constexpr const char *StretPostfix = "_stret";
  static constexpr size_t StretLength = length(StretPostfix);
  static constexpr const char *MsgLookupPrefix = "_objc_msgLookup";
  static constexpr size_t MsgLookupLength = length(MsgLookupPrefix);

  // This is an inverse of `CGObjCCommonMac::GetNameForMethod`.
  // TODO: Find out whether there aren't any Objective-C method name parsers
  // somewhere in the LLVM ecosystem already.
  ClassExportPtr findClassMethod(const std::string &Name);
  bool isInteresting(const std::string &Name, ExportPtr &Exp);
  bool isInterestingForWindows(const std::string &Name, ExportPtr &Exp,
                               bool IgnoreDuplicates = false);
  ExportPtr addExport(std::string &&Name) {
    return iOSExps.insert(ExportEntry(move(Name))).first;
  };
};

// !defined(HACONTEXT_HPP)
#endif

// HAContext.hpp

#ifndef HACONTEXT_HPP
#define HACONTEXT_HPP

#include "Common.hpp"

#include <llvm/IR/DerivedTypes.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

// Wrapper over container iterator. Plus extra `operator bool`.
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
struct ClassExport;
using DylibList = std::set<Dylib>;
using DylibPtr = ContainerPtr<DylibList>;
using ExportList = std::set<ExportEntry>;
using ExportPtr = ContainerPtr<ExportList>;
using ClassExportList = std::set<ClassExport>;
using ClassExportPtr = ContainerPtr<ClassExportList>;
using GroupList = std::vector<DLLGroup>;
using GroupPtr = size_t;
using DLLEntryList = std::vector<DLLEntry>;
using DLLPtr = size_t;

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

// The following structs are used in `std::set`s, so they have one key field and
// `operator<` that compares just this field. Other fields are values and hence
// marked `mutable` (because otherwise, `std::set` returns everyhing as `const`,
// so that we don't change the ordering which would break internal structures of
// `std::set`).

struct ExportEntry {
  ExportEntry(std::string Name)
      : Name(move(Name)), Status(ExportStatus::NotFound), RVA(0), Type(nullptr),
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
  Dylib(std::string Name) : Name(move(Name)) {}

  std::string Name;
  mutable std::vector<ExportPtr> Exports;

  bool operator<(const Dylib &Other) const { return Name < Other.Name; }
};

struct ClassExport {
  ClassExport(std::string Name) : Name(move(Name)) {}

  std::string Name;
  mutable std::vector<DylibPtr> Dylibs;

  bool operator<(const ClassExport &Other) const { return Name < Other.Name; }
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

  bool isClassMethod(const std::string &Name);
  // This is an inverse of `CGObjCCommonMac::GetNameForMethod`.
  // TODO: Find out whether there aren't any Objective-C method name parsers
  // somewhere in the LLVM ecosystem already.
  ClassExportPtr findClassMethod(const std::string &Name);
  bool isInteresting(const std::string &Name, ExportPtr &Exp);
  bool isInterestingForWindows(const std::string &Name, ExportPtr &Exp,
                               uint32_t RVA, bool IgnoreDuplicates = false);
  ExportPtr addExport(std::string &&Name) {
    return iOSExps.insert(ExportEntry(move(Name))).first;
  };
};

// !defined(HACONTEXT_HPP)
#endif

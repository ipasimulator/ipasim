// HAContext.hpp

#ifndef IPASIM_HA_CONTEXT_HPP
#define IPASIM_HA_CONTEXT_HPP

#include "ipasim/Common.hpp"

#include <cstdint>
#include <filesystem>
#include <llvm/IR/DerivedTypes.h>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ipasim {

enum class LibType { None = 0, Dylib = 0x1, DLL = 0x2, Both = 0x3 };

// TODO: Generalize this for all enums.
constexpr bool operator&(LibType Value, LibType Flag) {
  return ((uint32_t)Value & (uint32_t)Flag) == (uint32_t)Flag;
}

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
  bool operator<(const ContainerPtr &Other) const {
    return *Value < *Other.Value;
  }
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
  ExportPtr ReferenceSymbol;
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
      : Name(move(Name)), Status(ExportStatus::NotFound), RVA(0),
        DylibType(nullptr), DLLType(nullptr), ObjCMethod(false),
        Messenger(false), Stret(false), Super(false), Super2(false),
        DylibStretOnly(false) {}

  std::string Name;
  mutable ExportStatus Status;
  mutable uint32_t RVA;
  mutable bool ObjCMethod : 1;
  mutable bool Messenger : 1;
  mutable bool Stret : 1;
  mutable bool Super : 1;
  mutable bool Super2 : 1;
  mutable bool DylibStretOnly : 1; // See #28.
  mutable GroupPtr DLLGroup;
  mutable DLLPtr DLL;
  mutable DylibPtr Dylib; // first Dylib that implements this function

  bool operator<(const ExportEntry &Other) const { return Name < Other.Name; }
  bool isTrivial() const {
    return !DylibStretOnly && !DylibType->getNumParams() &&
           DylibType->getReturnType()->isVoidTy();
  }
  void setType(llvm::FunctionType *T) const {
    assert(!DLLType && "Cannot change type after DLLType has been generated.");
    DylibType = T;
  }
  template <LibType T> llvm::FunctionType *getType() const;
  llvm::FunctionType *getDylibType() const { return getType<LibType::Dylib>(); }
  llvm::FunctionType *getDLLType() const { return getType<LibType::DLL>(); }

private:
  // `nullptr` means this is not a function
  mutable llvm::FunctionType *DylibType;
  mutable llvm::FunctionType *DLLType;
  mutable std::vector<llvm::Type *> DLLArgs;
};

struct Dylib {
  Dylib(std::string Name) : Name(move(Name)) {}

  std::string Name;
  mutable std::vector<ExportPtr> Exports;
  mutable std::set<std::pair<GroupPtr, DLLPtr>> ReExports; // See #23.

  bool operator<(const Dylib &Other) const { return Name < Other.Name; }
};

struct ClassExport {
  ClassExport(std::string Name) : Name(move(Name)) {}

  std::string Name;
  // TODO: It is allowed for multiple libraries to export the same class. But
  // currently, we generate wrappers and stubs for all the class's methods in
  // all the wrapper libraries. We should reexport them instead.
  mutable std::vector<DylibPtr> Dylibs;

  bool operator<(const ClassExport &Other) const { return Name < Other.Name; }
};

class HAContext {
public:
  ExportList iOSExps;
  DylibList iOSLibs;
  ClassExportList iOSClasses;
  GroupList DLLGroups;

  static constexpr ConstexprString MsgSendPrefix = "_objc_msgSend";
  static constexpr ConstexprString StretPostfix = "_stret";
  static constexpr ConstexprString MsgLookupPrefix = "_objc_msgLookup";
  static constexpr ConstexprString MsgNilPrefix = "__objc_msgNil";

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

// =============================================================================
// Iterators
// =============================================================================

template <typename T, typename FTy> class MappedContainer {
public:
  using ItTy = decltype(std::declval<T>().begin());

  MappedContainer(T &&Container, FTy &&Func)
      : Container(std::forward<T>(Container)), Func(std::forward<FTy>(Func)) {}

  auto begin() { return Func(Container.begin()); }
  auto end() { return Func(Container.end()); }

private:
  T &&Container;
  FTy Func;
};
template <typename T, typename FTy>
auto mapContainer(T &&Container, FTy &&Func) {
  return MappedContainer<T, FTy>(std::forward<T>(Container),
                                 std::forward<FTy>(Func));
}
template <typename T, typename FTy>
auto mapIterator(T &&Container, FTy &&Func) {
  return mapContainer(std::forward<T>(Container),
                      [Func(std::forward<FTy>(Func))](auto It) {
                        return llvm::map_iterator(std::move(It), Func);
                      });
}

// Should work for, e.g., `T = std::vector<std::vector<uint32_t>::iterator>`.
// Dereferences iterated values.
template <typename T> auto deref(T &&Container) {
  return mapIterator(std::forward<T>(Container),
                     [](auto Value) { return *Value; });
}

template <typename ItTy>
class WithPtrsIterator
    : public llvm::iterator_adaptor_base<WithPtrsIterator<ItTy>, ItTy> {
public:
  WithPtrsIterator(ItTy It)
      : WithPtrsIterator::iterator_adaptor_base(std::move(It)) {}

  auto getCurrent() { return this->I; }
  auto operator*() { return std::make_pair(this->I, *this->I); }
};

// Should work for, e.g., `T = std::vector<uint32_t>`. Maps iterated values to
// pairs of their iterators and themselves.
template <typename T> auto withPtrs(T &&Container) {
  return mapContainer(std::forward<T>(Container),
                      [](auto It) { return WithPtrsIterator(std::move(It)); });
}

class Counter {
public:
  template <typename T> auto operator()(T &Value) {
    return std::pair<size_t, T &>(Idx++, Value);
  }

private:
  size_t Idx = 0;
};

// Maps iterated values to pairs of their indices and themselves.
template <typename T> auto withIndices(T &&Container) {
  return mapIterator(std::forward<T>(Container), Counter());
}

} // namespace ipasim

// !defined(IPASIM_HA_CONTEXT_HPP)
#endif

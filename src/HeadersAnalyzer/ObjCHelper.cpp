// ObjCHelper.cpp: Implementation of class `ObjCMethodScout`.

#include "ipasim/ObjCHelper.hpp"

#include "ipasim/Output.hpp"

using namespace ipasim;
using namespace llvm;
using namespace llvm::object;
using namespace std;

set<ipasim::ObjCMethod> ObjCMethodScout::discoverMethods(const string &DLLPath,
                                                         COFFObjectFile *COFF) {
  // Find pointer to Mach-O header.
  const coff_section *MhdrSection;
  if (error_code Error = COFF->getSection(".mhdr", MhdrSection)) {
    Log.error(Error.message());
    return set<ipasim::ObjCMethod>();
  }
  uint32_t Offset = MhdrSection->PointerToRawData;

  // Load the DLL starting with the Mach-O header.
  auto MB(MemoryBuffer::getFileSlice(
      DLLPath, COFF->getMemoryBufferRef().getBufferSize() - Offset, Offset));
  if (error_code Error = MB.getError()) {
    Log.error(Error.message());
    return set<ipasim::ObjCMethod>();
  }
  auto MachO(ObjectFile::createMachOObjectFile(**MB, /* MachOPoser */ true));
  if (!MachO) {
    Log.error(toString(MachO.takeError()));
    return set<ipasim::ObjCMethod>();
  }

  ObjCMethodScout Scout(COFF, move(*MB), move(*MachO));
  Scout.discoverMethods();
  return move(Scout.Results);
}

void ObjCMethodScout::discoverMethods() {
  Meta.forceObjC2(true);
  findMethods(Meta.classes());
  findMethods(Meta.categories());
  findMethods(Meta.protocols());
}

template <typename ListTy>
void ObjCMethodScout::findMethods(Expected<ListTy> &&List) {
  if (!List) {
    Log.error(toString(List.takeError()));
    return;
  }
  for (auto Ref : *List) {
    auto Element = *Ref;
    if (!Element) {
      Log.error(toString(Element.takeError()));
      continue;
    }

    auto Name = Element->getName();
    if (!Name) {
      Log.error(toString(Name.takeError()));
      continue;
    }

    registerMethods(*Name, Element->instanceMethods(), /* Static */ false);
    registerMethods(*Name, Element->classMethods(), /* Static */ true);
    registerOptionalMethods(*Name, *Element);
  }
}

template <typename ElementTy>
void ObjCMethodScout::registerOptionalMethods(StringRef, const ElementTy &) {}
template <>
void ObjCMethodScout::registerOptionalMethods<ObjCProtocol>(
    StringRef ProtocolName, const ObjCProtocol &Protocol) {
  registerMethods(ProtocolName, Protocol.optionalInstanceMethods(),
                  /* Static */ false);
  registerMethods(ProtocolName, Protocol.optionalClassMethods(),
                  /* Static */ true);
}

void ObjCMethodScout::registerMethods(StringRef ElementName,
                                      Expected<ObjCMethodList> &&Methods,
                                      bool Static) {
  if (!Methods) {
    Log.error(toString(Methods.takeError()));
    return;
  }
  for (llvm::ObjCMethod &Method : *Methods) {
    auto Imp = Meta.getResolvedValueFromAddress32(
        Method.getRawContent().getValue() + 8);
    if (!Imp) {
      Log.error(toString(Imp.takeError()));
      continue;
    }

    // Ignore `NULL` methods.
    if (!*Imp)
      continue;

    auto Name = Method.getName();
    if (!Name) {
      Log.error(toString(Name.takeError()));
      continue;
    }

    uint32_t RVA = *Imp - COFF->getImageBase();
    Results.insert({RVA, (Static ? "+[" : "-[") + ElementName.str() + " " +
                             Name->str() + "]"});
  }
}

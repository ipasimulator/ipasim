// ObjCHelper.cpp

#include "ipasim/ObjCHelper.hpp"

#include "ipasim/ErrorReporting.hpp"

using namespace ipasim;
using namespace llvm;
using namespace llvm::object;
using namespace std;

set<uint32_t> ObjCMethodScout::discoverMethods(const string &DLLPath,
                                               COFFObjectFile *COFF) {
  // Find pointer to Mach-O header.
  const coff_section *MhdrSection;
  if (error_code Error = COFF->getSection(".mhdr", MhdrSection)) {
    Log.error(Error.message());
    return set<uint32_t>();
  }
  uint32_t Offset = MhdrSection->PointerToRawData;

  // Load the DLL starting with the Mach-O header.
  auto MB(MemoryBuffer::getFileSlice(
      DLLPath, COFF->getMemoryBufferRef().getBufferSize() - Offset, Offset));
  if (error_code Error = MB.getError()) {
    Log.error(Error.message());
    return set<uint32_t>();
  }
  auto MachO(ObjectFile::createMachOObjectFile(**MB, /* MachOPoser */ true));
  if (!MachO) {
    Log.error(toString(MachO.takeError()));
    return set<uint32_t>();
  }

  ObjCMethodScout Scout(COFF, move(*MB), move(*MachO));
  Scout.discoverMethods();
  return move(Scout.RVAs);
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
    registerMethods(Element->instanceMethods());
    registerMethods(Element->classMethods());
    registerOptionalMethods(*Element);
  }
}

template <typename ElementTy>
void ObjCMethodScout::registerOptionalMethods(const ElementTy &) {}
template <>
void ObjCMethodScout::registerOptionalMethods<ObjCProtocol>(
    const ObjCProtocol &Protocol) {
  registerMethods(Protocol.optionalInstanceMethods());
  registerMethods(Protocol.optionalClassMethods());
}

void ObjCMethodScout::registerMethods(Expected<ObjCMethodList> &&Methods) {
  if (!Methods) {
    Log.error(toString(Methods.takeError()));
    return;
  }
  for (ObjCMethod &Method : *Methods) {
    auto Imp = Meta.getResolvedValueFromAddress32(
        Method.getRawContent().getValue() + 8);
    if (!Imp) {
      Log.error(toString(Imp.takeError()));
      continue;
    }
    if (*Imp)
      RVAs.insert(*Imp - COFF->getImageBase());
  }
}

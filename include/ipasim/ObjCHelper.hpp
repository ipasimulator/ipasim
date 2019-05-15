// ObjCHelper.hpp: Definition of class `ObjCMethodScout`.

#ifndef IPASIM_OBJC_HELPER_HPP
#define IPASIM_OBJC_HELPER_HPP

#include <llvm/ObjCMetadata/ObjCMachOBinary.h>
#include <llvm/Object/COFF.h>
#include <set>
#include <string>

namespace ipasim {

// Result of Objective-C method scouting, see below.
struct ObjCMethod {
  uint32_t RVA;
  std::string Name;

  bool operator<(const ObjCMethod &Other) const { return RVA < Other.RVA; }
};

// Helper class that can discover Objective-C methods from binary's metadata.
// Note that the Mach-O binary being analyzed is the file, not the image loaded
// into memory at runtime (cf. class `MachO`).
class ObjCMethodScout {
public:
  static std::set<ObjCMethod>
  discoverMethods(const std::string &DLLPath,
                  llvm::object::COFFObjectFile *COFF);

private:
  std::set<ObjCMethod> Results;
  llvm::object::COFFObjectFile *COFF;
  std::unique_ptr<llvm::MemoryBuffer> MB;
  std::unique_ptr<llvm::object::MachOObjectFile> MachO;
  llvm::MachOMetadata Meta;

  ObjCMethodScout(llvm::object::COFFObjectFile *COFF,
                  std::unique_ptr<llvm::MemoryBuffer> &&MB,
                  std::unique_ptr<llvm::object::MachOObjectFile> &&MachO)
      : COFF(COFF), MB(std::move(MB)), MachO(std::move(MachO)),
        Meta(this->MachO.get()) {}

  void discoverMethods();
  template <typename ListTy> void findMethods(llvm::Expected<ListTy> &&List);
  template <typename ElementTy>
  void registerOptionalMethods(llvm::StringRef ElementName,
                               const ElementTy &Element);
  void registerMethods(llvm::StringRef ElementName,
                       llvm::Expected<llvm::ObjCMethodList> &&Methods,
                       bool Static);
};

} // namespace ipasim

// !defined(IPASIM_OBJC_HELPER_HPP)
#endif

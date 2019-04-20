// ObjCHelper.hpp

#ifndef IPASIM_OBJC_HELPER_HPP
#define IPASIM_OBJC_HELPER_HPP

#include <llvm/ObjCMetadata/ObjCMachOBinary.h>
#include <llvm/Object/COFF.h>
#include <set>
#include <string>

namespace ipasim {

class ObjCMethodScout {
public:
  static std::set<uint32_t> discoverMethods(const std::string &DLLPath,
                                            llvm::object::COFFObjectFile *COFF);

private:
  std::set<uint32_t> RVAs;
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
  void registerMethods(llvm::Expected<llvm::ObjCMethodList> &&Methods);
};

} // namespace ipasim

// !defined(IPASIM_OBJC_HELPER_HPP)
#endif

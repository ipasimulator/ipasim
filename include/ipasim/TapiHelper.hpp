// TapiHelper.hpp

#ifndef IPASIM_TAPI_HELPER_HPP
#define IPASIM_TAPI_HELPER_HPP

#include "ipasim/HAContext.hpp"

#include <tapi/Core/FileManager.h>
#include <tapi/Core/InterfaceFile.h>
#include <tapi/Core/InterfaceFileManager.h>

namespace ipasim {

class TBDHandler {
public:
  TBDHandler(HAContext &HAC);
  void handleFile(const std::string &Path);

private:
  void addExport(DylibPtr Dylib, std::string &&Name);

  HAContext &HAC;
  tapi::internal::FileManager FM;
  tapi::internal::InterfaceFileManager IFM;
};

} // namespace ipasim

// !defined(IPASIM_TAPI_HELPER_HPP)
#endif

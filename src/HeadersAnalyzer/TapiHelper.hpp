// TapiHelper.hpp

#ifndef TAPIHELPER_HPP
#define TAPIHELPER_HPP

#include "HAContext.hpp"

#include <tapi/Core/FileManager.h>
#include <tapi/Core/InterfaceFile.h>
#include <tapi/Core/InterfaceFileManager.h>

class TBDHandler {
public:
  TBDHandler(HAContext &HAC);
  void HandleFile(const std::string &Path);

private:
  HAContext &HAC;
  tapi::internal::FileManager FM;
  tapi::internal::InterfaceFileManager IFM;
};

// !defined(TAPIHELPER_HPP)
#endif

// IpaSimulator.hpp

#ifndef IPASIM_IPA_SIMULATOR_HPP
#define IPASIM_IPA_SIMULATOR_HPP

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/Emulator.hpp"
#include "ipasim/Logger.hpp"
#include "ipasim/SysTranslator.hpp"
#include "ipasim/TextBlockStream.hpp"

#include <string>
#include <unicorn/unicorn.h>
#include <winrt/Windows.ApplicationModel.Activation.h>

#if defined(IpaSimLibrary_EXPORTS)
#define IPASIM_EXPORT __declspec(dllexport)
#else
#define IPASIM_EXPORT __declspec(dllimport)
#endif
#define IPASIM_API extern "C" IPASIM_EXPORT

namespace ipasim {

class IpaSimulator {
public:
  IpaSimulator();

  Emulator Emu;
  DynamicLoader Dyld;
  std::string MainBinary;
  SysTranslator Sys;

  IPASIM_EXPORT bool start(const winrt::hstring &Path,
                           const winrt::Windows::ApplicationModel::Activation::
                               LaunchActivatedEventArgs &LaunchArgs);
};

IPASIM_EXPORT extern IpaSimulator IpaSim;
extern Logger<LogStream> Log;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_HPP)
#endif

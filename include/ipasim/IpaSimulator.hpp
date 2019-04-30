// IpaSimulator.hpp

#ifndef IPASIM_IPA_SIMULATOR_HPP
#define IPASIM_IPA_SIMULATOR_HPP

#include "ipasim/Common.hpp"
#include "ipasim/DynamicLoader.hpp"
#include "ipasim/Emulator.hpp"
#include "ipasim/Logger.hpp"
#include "ipasim/SysTranslator.hpp"
#include "ipasim/TextBlockStream.hpp"

#include <string>
#include <unicorn/unicorn.h>
#include <winrt/Windows.ApplicationModel.Activation.h>

namespace ipasim {

class IpaSimulator {
public:
  IpaSimulator();

  Emulator Emu;
  DynamicLoader Dyld;
  std::string MainBinary;
  SysTranslator Sys;
  TextBlockProvider LogText;
};

IPASIM_EXPORT bool start(
    const winrt::hstring &Path,
    const winrt::Windows::ApplicationModel::Activation::LaunchActivatedEventArgs
        &LaunchArgs);
IPASIM_EXPORT TextBlockProvider &logText();
// TODO: This is just a workaround, because MSVC cannot compile `Log.error`
// calls.
IPASIM_EXPORT void error(const char *Message);

extern IpaSimulator IpaSim;
extern Logger<LogStream> Log;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_HPP)
#endif

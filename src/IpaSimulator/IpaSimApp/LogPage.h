#pragma once

#include "LogPage.g.h"

namespace winrt::IpaSimApp::implementation {

struct LogPage : LogPageT<LogPage> {
  LogPage();

  void Log(const winrt::hstring &Message);
};

} // namespace winrt::IpaSimApp::implementation

namespace winrt::IpaSimApp::factory_implementation {

struct LogPage : LogPageT<LogPage, implementation::LogPage> {};

} // namespace winrt::IpaSimApp::factory_implementation

#pragma once

#include "LogPage.g.h"

namespace winrt::IpaSimApp::implementation {

struct LogPage : LogPageT<LogPage> {
  LogPage();
};

} // namespace winrt::IpaSimApp::implementation

namespace winrt::IpaSimApp::factory_implementation {

struct LogPage : LogPageT<LogPage, implementation::LogPage> {};

} // namespace winrt::IpaSimApp::factory_implementation

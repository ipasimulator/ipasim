// Logger.hpp: A header-only self-contained logger.

#ifndef IPASIM_LOGGER_HPP
#define IPASIM_LOGGER_HPP

#include <string>
#include <winrt/base.h>

namespace ipasim {

class EndToken {};
class WinErrorToken {};
class AppendWinErrorToken {};

class DebugStream;
using StreamHandler = std::function<void(DebugStream &)>;

class DebugStream {
public:
  DebugStream &operator<<(const std::string &S) { return *this << S.c_str(); }
  DebugStream &operator<<(const char *S) {
    OutputDebugStringA(S);
    return *this;
  }
  DebugStream &operator<<(const std::wstring &S) { return *this << S.c_str(); }
  DebugStream &operator<<(const wchar_t *S) {
    OutputDebugStringW(S);
    return *this;
  }
  DebugStream &operator<<(EndToken) { return *this << ".\n"; }
  DebugStream &operator<<(WinErrorToken) {
    using namespace winrt;

    // From `winrt::throw_last_error`
    hresult_error Err(HRESULT_FROM_WIN32(GetLastError()));
    return *this << Err.message().c_str();
  }
  DebugStream &operator<<(AppendWinErrorToken) {
    return *this << EndToken() << WinErrorToken() << "\n";
  }
  template <typename T>
  std::enable_if_t<
      std::is_same_v<decltype(std::to_string(std::declval<T>())), std::string>,
      DebugStream &>
  operator<<(const T &Any) {
    return *this << std::to_string(Any).c_str();
  }
  DebugStream &operator<<(const StreamHandler &Handler) {
    Handler(*this);
    return *this;
  }
};

class Logger {
public:
  void error(const std::string &Message) {
    error</* AppendLastError */ false>(Message);
  }
  void winError(const std::string &Message) {
    error</* AppendLastError */ true>(Message);
  }
  DebugStream &error() { return errs() << "Error: "; }
  DebugStream &info() { return infs() << "Info: "; }
  DebugStream &errs() { return DS; }
  DebugStream &infs() { return DS; }
  EndToken end() { return EndToken(); }
  WinErrorToken winError() { return WinErrorToken(); }
  AppendWinErrorToken appendWinError() { return AppendWinErrorToken(); }
  void throwFatal(const char *Message) { throw std::runtime_error(Message); }

private:
  template <bool AppendLastError> void error(const std::string &Message) {
    error() << Message << end();
    if constexpr (AppendLastError)
      errs() << winError() << "\n";
  }

  DebugStream DS;
};

} // namespace ipasim

// !defined(IPASIM_LOGGER_HPP)
#endif

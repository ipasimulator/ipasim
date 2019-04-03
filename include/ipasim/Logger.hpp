// Logger.hpp: A header-only self-contained logger.

#ifndef IPASIM_LOGGER_HPP
#define IPASIM_LOGGER_HPP

#include <iostream>
#include <ostream>
#include <string>
#include <winrt/base.h>

namespace ipasim {

class EndToken {};
class WinErrorToken {};
class AppendWinErrorToken {};

template <typename DerivedTy> class Stream {
public:
  using Handler = std::function<void(DerivedTy &)>;

  // Note that all `operator<<`s must be here and none inside `DerivedTy`,
  // because otherwise only those in `DerivedTy` would be searched.
  DerivedTy &operator<<(const char *S) { return d().write(S); }
  DerivedTy &operator<<(const wchar_t *S) { return d().write(S); }
  DerivedTy &operator<<(const std::string &S) { return d() << S.c_str(); }
  DerivedTy &operator<<(const std::wstring &S) { return d() << S.c_str(); }
  DerivedTy &operator<<(EndToken) { return d() << ".\n"; }
  DerivedTy &operator<<(WinErrorToken) {
    using namespace winrt;

    // From `winrt::throw_last_error`
    hresult_error Err(HRESULT_FROM_WIN32(GetLastError()));
    return d() << Err.message().c_str();
  }
  DerivedTy &operator<<(AppendWinErrorToken) {
    return d() << EndToken() << WinErrorToken() << "\n";
  }
  template <typename T>
  std::enable_if_t<
      std::is_same_v<decltype(std::to_string(std::declval<T>())), std::string>,
      DerivedTy &>
  operator<<(const T &Any) {
    return d() << std::to_string(Any).c_str();
  }
  DerivedTy &operator<<(const Handler &Handler) {
    Handler(d());
    return d();
  }

private:
  DerivedTy &d() { return *static_cast<DerivedTy *>(this); }
};

class DebugStream : public Stream<DebugStream> {
public:
  DebugStream &write(const char *S) {
    OutputDebugStringA(S);
    return *this;
  }
  DebugStream &write(const wchar_t *S) {
    OutputDebugStringW(S);
    return *this;
  }
};

class StdStream : public Stream<StdStream> {
public:
  StdStream(std::ostream &Str, std::wostream &WStr) : Str(Str), WStr(WStr) {}

  StdStream &write(const char *S) {
    Str << S;
    return *this;
  }
  StdStream &write(const wchar_t *S) {
    WStr << S;
    return *this;
  }

  static StdStream out() { return StdStream(std::cout, std::wcout); }
  static StdStream err() { return StdStream(std::cerr, std::wcerr); }

private:
  std::ostream &Str;
  std::wostream &WStr;
};

template <typename StreamTy> class Logger {
public:
  Logger() = default;
  Logger(StreamTy &&O, StreamTy &&E) : O(std::move(O)), E(std::move(E)) {}

  void error(const std::string &Message) {
    error</* AppendLastError */ false>(Message);
  }
  void winError(const std::string &Message) {
    error</* AppendLastError */ true>(Message);
  }
  StreamTy &error() { return errs() << "Error: "; }
  StreamTy &info() { return infs() << "Info: "; }
  StreamTy &errs() { return E; }
  StreamTy &infs() { return O; }
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

  StreamTy O, E;
};

using DebugLogger = Logger<DebugStream>;
using StdLogger = Logger<StdStream>;

} // namespace ipasim

// !defined(IPASIM_LOGGER_HPP)
#endif

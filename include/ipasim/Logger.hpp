// Logger.hpp: A header-only self-contained logger.

#ifndef IPASIM_LOGGER_HPP
#define IPASIM_LOGGER_HPP

#include <functional>
#include <iostream>
#include <ostream>
#include <string>

#if !defined(IPASIM_NO_WINDOWS_ERRORS)
// From <winnt.h>
// TODO: How are these undefined?
#define LANG_NEUTRAL 0x00
#define SUBLANG_DEFAULT 0x01 // user default

#include <winrt/base.h>
#else
__declspec(dllimport) __stdcall void OutputDebugStringA(const char *);
__declspec(dllimport) __stdcall void OutputDebugStringW(const wchar_t *);
#endif

#define IPASIM_NORETURN [[noreturn]]

namespace ipasim {

class FatalError : public std::runtime_error {
public:
  FatalError(const char *Message) : runtime_error(Message) {}
};

class EndToken {};
class WinErrorToken {};
class AppendWinErrorToken {};
class FatalEndToken {
public:
  FatalEndToken(const char *Message) : Message(Message) {}

  const char *Message;
};

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
#if !defined(IPASIM_NO_WINDOWS_ERRORS)
    using namespace winrt;

    // From `winrt::throw_last_error`
    hresult_error Err(HRESULT_FROM_WIN32(GetLastError()));
    return d() << Err.message().c_str();
#else
    return d() << "IPASIM_NO_WINDOWS_ERRORS";
#endif
  }
  DerivedTy &operator<<(AppendWinErrorToken) {
    return d() << EndToken() << WinErrorToken() << "\n";
  }
  IPASIM_NORETURN DerivedTy &operator<<(FatalEndToken T) {
    d() << EndToken();
    throw FatalError(T.Message);
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

  static constexpr bool IsIpasimStream = true;
  friend struct is_stream;
};

// SFINAE magic
struct is_stream {
  struct a {};
  struct b : a {};

  template <typename> static constexpr bool getValue(a) { return false; }
  template <typename StreamTy, bool Result = StreamTy::IsIpasimStream>
  static constexpr bool getValue(b) {
    return Result;
  }
};
template <typename StreamTy>
constexpr bool is_stream_v = is_stream::getValue<StreamTy>(is_stream::b());

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

  void error(const std::string &Message) { error() << Message << end(); }
  void info(const std::string &Message) { info() << Message << end(); }
  void warning(const std::string &Message) { warning() << Message << end(); }
  void winError(const std::string &Message) {
    error(Message);
    errs() << winError() << "\n";
  }
  IPASIM_NORETURN void fatalError(const std::string &Message) {
    error(Message);
    throw FatalError(Message.c_str());
  }
  StreamTy &errs() { return E; }
  StreamTy &infs() { return O; }
  StreamTy &warns() { return E; }
  StreamTy &error() { return errs() << "Error: "; }
  StreamTy &info() { return infs() << "Info: "; }
  StreamTy &warning() { return warns() << "Warning: "; }
  EndToken end() { return EndToken(); }
  WinErrorToken winError() { return WinErrorToken(); }
  AppendWinErrorToken appendWinError() { return AppendWinErrorToken(); }
  FatalEndToken fatalEnd(const char *Message) { return FatalEndToken(Message); }
  FatalEndToken fatalEnd() { return FatalEndToken("Fatal error occurred."); }

private:
  StreamTy O, E;
};

using DebugLogger = Logger<DebugStream>;
using StdLogger = Logger<StdStream>;

} // namespace ipasim

// !defined(IPASIM_LOGGER_HPP)
#endif

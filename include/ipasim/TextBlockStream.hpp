// TextBlockStream.hpp

#ifndef IPASIM_TEXT_BLOCK_STREAM_HPP
#define IPASIM_TEXT_BLOCK_STREAM_HPP

#include "ipasim/Logger.hpp"

#include <winrt/Windows.UI.Xaml.Controls.h>

namespace ipasim {

class TextBlockProvider {
public:
  TextBlockProvider() : TB(nullptr) {}

  void init(winrt::Windows::UI::Xaml::Controls::TextBlock TextBlock) {
    TB = TextBlock;
  }
  winrt::Windows::UI::Xaml::Controls::TextBlock get() { return TB; }

private:
  winrt::Windows::UI::Xaml::Controls::TextBlock TB;
};

class TextBlockStream : public Stream<TextBlockStream> {
public:
  TextBlockStream(bool Error, TextBlockProvider &TBP)
      : Error(Error), TBP(TBP) {}

  TextBlockStream &write(const char *S) { return write(winrt::to_hstring(S)); }
  TextBlockStream &write(const wchar_t *S) { return write(winrt::hstring(S)); }

private:
  bool Error;
  TextBlockProvider &TBP;

  TextBlockStream &write(const winrt::hstring &S);
};

using LogStream = AggregateStream<DebugStream, TextBlockStream>;

} // namespace ipasim

// !defined(IPASIM_TEXT_BLOCK_STREAM_HPP)
#endif

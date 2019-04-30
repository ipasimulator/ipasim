// TextBlockStream.hpp

#ifndef IPASIM_TEXT_BLOCK_STREAM_HPP
#define IPASIM_TEXT_BLOCK_STREAM_HPP

#include "ipasim/Logger.hpp"

#include <winrt/Windows.UI.Xaml.Controls.h>

namespace ipasim {

class TextBlockStream : public Stream<TextBlockStream> {
public:
  TextBlockStream(bool Error) : Error(Error), TB(nullptr) {}

  void init(const winrt::Windows::UI::Xaml::Controls::TextBlock &TextBlock) {
    TB = TextBlock;
  }
  TextBlockStream &write(const char *S) { return write(winrt::to_hstring(S)); }
  TextBlockStream &write(const wchar_t *S) { return write(winrt::hstring(S)); }

private:
  bool Error;
  winrt::Windows::UI::Xaml::Controls::TextBlock TB;

  TextBlockStream &write(const winrt::hstring &S);
};

using LogStream = TextBlockStream;

} // namespace ipasim

// !defined(IPASIM_TEXT_BLOCK_STREAM_HPP)
#endif

// TextBlockStream.cpp

#include "ipasim/TextBlockStream.hpp"

#include <winrt/Windows.UI.Xaml.Documents.h>
#include <winrt/Windows.UI.Xaml.Media.h>

using namespace ipasim;
using namespace winrt;
using namespace Windows::UI;
using namespace Windows::UI::Xaml::Documents;
using namespace Windows::UI::Xaml::Media;

TextBlockStream &TextBlockStream::write(const hstring &S) {
  Run R;
  R.Text(S);
  if (Error)
    R.Foreground(SolidColorBrush(Colors::DarkRed()));
  TB.Inlines().Append(R);

  return *this;
}

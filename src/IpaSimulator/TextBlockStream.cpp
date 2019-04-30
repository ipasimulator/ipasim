// TextBlockStream.cpp

#include "ipasim/TextBlockStream.hpp"

#include <winrt/Windows.UI.Core.h>
#include <winrt/Windows.UI.Xaml.Documents.h>
#include <winrt/Windows.UI.Xaml.Media.h>

using namespace ipasim;
using namespace winrt;
using namespace Windows::UI;
using namespace Windows::UI::Core;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Documents;
using namespace Windows::UI::Xaml::Media;

TextBlockStream &TextBlockStream::write(const hstring &S) {
  TextBlock TB(TBP.get());
  TB.Dispatcher().RunAsync(CoreDispatcherPriority::Normal, [this, S, TB]() {
    Run R;
    R.Text(S);
    if (Error)
      R.Foreground(SolidColorBrush(Colors::Red()));
    TB.Inlines().Append(R);
  });
  return *this;
}

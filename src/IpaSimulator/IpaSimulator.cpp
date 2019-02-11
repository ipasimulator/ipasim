#include <winrt/Windows.Foundation.Metadata.h>

using namespace winrt;
using namespace Windows::Foundation::Metadata;

int main() {
  init_apartment();

  try {
    bool const rs4 = ApiInformation::IsApiContractPresent(
        L"Windows.Foundation.UniversalApiContract", 6);
    printf("Am I running on Redstone 4? %s\n", rs4 ? "Yes!" : "No. :(");
  } catch (const hresult_error &ex) {
    printf("Error: %ls\n", ex.message().c_str());
  }
}

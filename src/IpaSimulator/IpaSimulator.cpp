#include <winrt/Windows.Foundation.Metadata.h>

using namespace winrt;
using namespace Windows::Foundation::Metadata;

__declspec(dllexport) int main() {
  try {
    bool const rs4 = ApiInformation::IsApiContractPresent(
        L"Windows.Foundation.UniversalApiContract", 6);
    printf("Am I running on Redstone 4? %s\n", rs4 ? "Yes!" : "No. :(");
    return rs4;
  } catch (const hresult_error &ex) {
    printf("Error: %ls\n", ex.message().c_str());
    return ex.to_abi();
  }
}

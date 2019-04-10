// See #24.
extern "C" __declspec(dllimport) double _scalb(double x, long exp);
extern "C" long double ldexpl(long double x, int exp) { return _scalb(x, exp); }

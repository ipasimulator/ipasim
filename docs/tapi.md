# TAPI

Forked from <https://github.com/ributzka/tapi>.
**TODO: Fork rather from (more) official source <https://opensource.apple.com/source/tapi/>.**

## Building

We don't build this directly, we just include some source files in project `HeadersAnalyzer`.
That is also what others do, see for example [Swift's `TBDGen`](https://github.com/apple/swift/blob/2f4e70bf7f4eee43bfb2f24d6215eb1f63c05d01/lib/TBDGen/).

We generate some header files using `clang-tblgen`, though.
Run `build_tapi.cmd` to do that.

## Comment tags

- `[must-quote]`: Changed `bool` -> `QuotingType`, `false` -> `QuotingType::None`, `true` -> `QuotingType::Double`.
  LLVM API probably evolved.
- `[no-dynamic]`: `ObjCProperty` does not contain method `isDynamic` and it seems it never did.
  **TODO: How could it work in the original code, then?**

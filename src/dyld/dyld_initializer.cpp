extern "C" char _mh_dylib_header;
extern "C" void _dyld_initialize(void *);
extern "C" void _objc_init(void);

extern "C" __attribute__((constructor(1))) void ipasim_initializer() {
  // Register itself within `dyld`.
  _dyld_initialize(&_mh_dylib_header);
  // Initialize the runtime if not already initialized.
  _objc_init();
}

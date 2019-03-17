set (ORIG_SOURCE_FILES
    src/allocator.c
    src/apply.c
    src/benchmark.c
    src/data.c
    #src/init.c
    src/introspection.c
    #src/io.c
    src/mach.c
    src/object.c
    src/once.c
    src/queue.c
    src/semaphore.c
    src/source.c
    src/time.c
    src/transform.c
    src/voucher.c
    src/protocol.defs
    src/provider.d
    src/allocator_internal.h
    src/data_internal.h
    src/inline_internal.h
    src/internal.h
    src/introspection_internal.h
    src/io_internal.h
    src/mach_internal.h
    src/object_internal.h
    src/queue_internal.h
    src/semaphore_internal.h
    src/shims.h
    src/source_internal.h
    src/trace.h
    src/voucher_internal.h
    src/event/event.c
    src/event/event_config.h
    src/event/event_epoll.c
    src/event/event_internal.h
    src/event/event_kevent.c
    src/firehose/firehose_internal.h
    src/shims/android_stubs.h
    src/shims/atomic.h
    src/shims/atomic_sfb.h
    src/shims/getprogname.h
    src/shims/hw_config.h
    #src/shims/linux_stubs.c
    src/shims/linux_stubs.h
    src/shims/lock.c
    src/shims/lock.h
    src/shims/perfmon.h
    src/shims/time.h
    src/shims/tsd.h
    src/shims/yield.h)
list (TRANSFORM ORIG_SOURCE_FILES PREPEND
    "${SOURCE_DIR}/deps/libdispatch/")

add_library (dispatch SHARED ${ORIG_SOURCE_FILES})

target_include_directories (dispatch PRIVATE
    "${SOURCE_DIR}/deps/libdispatch"
    "${SOURCE_DIR}/deps/libdispatch/src"
    "${SOURCE_DIR}/deps/libdispatch/private"
    # From `/src/objc/CMakeLists.txt`
    "${SOURCE_DIR}/src/objc/include"
    "${SOURCE_DIR}/deps/apple-headers"
    "${SOURCE_DIR}/deps/libclosure")

target_compile_definitions (dispatch PRIVATE
    __APPLE__
    # From `/src/objc/CMakeLists.txt`
    OBJC_PORT
    __OBJC2__=1)

target_compile_options (dispatch PRIVATE
    -Wno-nullability-completeness
    # From `/src/objc/CMakeLists.txt`
    -fblocks
    -fobjc-runtime=macosx-10.13.0)

target_link_libraries (dispatch PRIVATE pthread objc)

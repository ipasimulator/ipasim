set (ORIG_SOURCE_FILES
    attr.c
    autostatic.c
    barrier.c
    cancel.c
    cleanup.c
    condvar.c
    create.c
    dll.c
    errno.c
    exit.c
    fork.c
    global.c
    misc.c
    mutex.c
    nonportable.c
    private.c
    rwlock.c
    sched.c
    semaphore.c
    signal.c
    spin.c
    sync.c
    tsd.c)
list (TRANSFORM ORIG_SOURCE_FILES PREPEND "${SOURCE_DIR}/deps/pthreads.2/")

add_library (pthread SHARED ${ORIG_SOURCE_FILES} stubs.c)

target_compile_definitions (pthread
    PRIVATE
        PTW32_BUILD
        __CLEANUP_C
    PUBLIC
        HAVE_STRUCT_TIMESPEC)

target_include_directories (pthread
    PUBLIC
        "${SOURCE_DIR}/deps/pthreads.2/"
        "${SOURCE_DIR}/src/pthread/")

add_dependencies (pthread prep)

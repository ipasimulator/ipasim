#ifndef _H_OBJC_LOCKS
#define _H_OBJC_LOCKS

#include <pthread.h>

// [Apple] Mix-in for classes that must not be copied.
class nocopy_t {
private:
	nocopy_t(const nocopy_t&) = delete;
	const nocopy_t& operator=(const nocopy_t&) = delete;
protected:
	nocopy_t() {}
	~nocopy_t() {}
};

struct fork_unsafe_lock_t { };

template <bool Debug>
class rwlock_tt : nocopy_t {
private:
	pthread_rwlock_t mLock;
public:
	rwlock_tt() : mLock(PTHREAD_RWLOCK_INITIALIZER) {
		lockdebug_remember_rwlock(this);
	}
	rwlock_tt(const fork_unsafe_lock_t unsafe)
		: mLock(PTHREAD_RWLOCK_INITIALIZER) {}
};

#if DEBUG
#   define LOCKDEBUG 1
#else
#	define LOCKDEBUG 0
#endif

using rwlock_t = rwlock_tt<LOCKDEBUG>;

// [Apple] Declarations of all locks used in the runtime.

extern rwlock_t selLock;

#endif // _H_OBJC_LOCKS

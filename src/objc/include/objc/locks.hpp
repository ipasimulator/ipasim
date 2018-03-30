#ifndef OBJC_LOCKS_H
#define OBJC_LOCKS_H

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

template <bool Debug> class rwlock_tt;

#if DEBUG
#   define LOCKDEBUG 1
#else
#	define LOCKDEBUG 0
#endif

using rwlock_t = rwlock_tt<LOCKDEBUG>;

// CHANGE: "extern" keyword was removed from these definitions,
// since it was most likely redundant.
void lockdebug_remember_rwlock(rwlock_tt<true> *lock);
void lockdebug_rwlock_read(rwlock_tt<true> *lock);
void lockdebug_rwlock_try_read_success(rwlock_tt<true> *lock);
void lockdebug_rwlock_unlock_read(rwlock_tt<true> *lock);
void lockdebug_rwlock_write(rwlock_tt<true> *lock);
void lockdebug_rwlock_try_write_success(rwlock_tt<true> *lock);
void lockdebug_rwlock_unlock_write(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_reading(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_writing(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_locked(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_unlocked(rwlock_tt<true> *lock);

static inline void lockdebug_remember_rwlock(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_read(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_try_read_success(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_unlock_read(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_write(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_try_write_success(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_unlock_write(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_reading(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_writing(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_locked(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_unlocked(rwlock_tt<false> *) { }

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

// [Apple] Declarations of all locks used in the runtime.

extern rwlock_t selLock;

#endif // OBJC_LOCKS_H

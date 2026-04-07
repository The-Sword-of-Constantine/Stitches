#pragma once
#include <fltKernel.h>


namespace kstd
{
	/*
	* Author: jacky (https://github.com/lzty)
	*/
	static constexpr ULONG       mutex_pool_tag = 'mTeX';
	static constexpr POOL_TYPE   mutex_pool_type = NonPagedPoolNx;

	using lock_queue_handle = KLOCK_QUEUE_HANDLE;

	enum class LockStrategy
	{
		FastMutex,
		GuardedMutex,
		ResourceLock,
		SpinLock,
		InStackQueueSpinLock
	};

	struct empty_mutex
	{
		void lock() {}
		bool tryLock() {}
		void unlock() {}
	};
	/*
	* Note:
	* ExAcquirePushLockExclusive(Shared) can also implement this sanmetics
	* but it requires windows version to be at least win10, using push lock in fltmgr to gain best compatibility
	*/
	class shared_mutex
	{
	public:

		using native_handle_type = PEX_PUSH_LOCK;

		shared_mutex() noexcept;
		~shared_mutex() noexcept;
		void lock() noexcept;
		bool tryLock() noexcept;
		void unlock() noexcept;
		void lock_shared() noexcept;
		bool try_lock_shared() noexcept;
		void unlock_shared() noexcept;
		native_handle_type native_handle() noexcept;

	private:
		EX_PUSH_LOCK m_PushLock;
	};

	template <typename _Mutex>
	class instack_scoped_lock
	{
	public:
		using mutex_type = _Mutex;

		explicit instack_scoped_lock(_Mutex& mutex)
			: m_mutex(mutex)
		{
			m_mutex.lock(&m_handle);
		}

		instack_scoped_lock(const instack_scoped_lock&) = delete;
		instack_scoped_lock operator=(const instack_scoped_lock&) = delete;

		~instack_scoped_lock()
		{
			m_mutex.unlock(&m_handle);
		}

	private:
		lock_queue_handle m_handle;
		_Mutex& m_mutex;
	};

	/*
	* wrapper class for mutex<InStackSpinLock, PoolTag>
	* for convenient usage like this
	* mutex.lock()
	* // ... do something
	* mutex.unlock()
	*/
	template <typename _Mutex>
	class instack_queue
	{
	public:
		using mutex_type = _Mutex;

		explicit instack_queue(_Mutex& mutex)
			: m_mutex(std::addressof(mutex))
		{

		}

		~instack_queue() = default;

		instack_queue(const instack_queue&) = delete;
		instack_queue operator=(const instack_queue&) = delete;

		void lock() noexcept
		{
			m_mutex->lock(&m_handle);
		}

		constexpr bool tryLock() noexcept(false)
		{
			terminate();
		}

		void unlock() noexcept
		{
			m_mutex->unlock(&m_handle);
		}

	private:
		lock_queue_handle m_handle;
		_Mutex* m_mutex;
	};

	template <LockStrategy Type, ULONG PoolTag = mutex_pool_tag> class mutex;


	template <ULONG PoolTag>
	class mutex<LockStrategy::FastMutex, PoolTag>
	{
	public:
		using native_handle_type = PFAST_MUTEX;

		mutex()
		{
			m_mutex = static_cast<PFAST_MUTEX>(
				ExAllocatePoolWithTag(mutex_pool_type, sizeof(FAST_MUTEX), PoolTag)
				);

			if (!m_mutex)
				return;

			ExInitializeFastMutex(m_mutex);
		}

		~mutex()
		{
			if (m_mutex)
			{
				ExFreePoolWithTag(m_mutex, PoolTag);
			}
		}

		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		void lock()
		{
			ExAcquireFastMutex(m_mutex);
		}

		bool tryLock()
		{
			return ExTryToAcquireFastMutex(m_mutex);
		}

		void unlock()
		{
			ExReleaseFastMutex(m_mutex);
		}

		native_handle_type native_handle() noexcept
		{
			return m_mutex;
		}

	private:
		PFAST_MUTEX m_mutex{};
	};

	template <ULONG PoolTag>
	class mutex<LockStrategy::GuardedMutex, PoolTag>
	{
	public:

		using native_handle_type = PKGUARDED_MUTEX;

		mutex() noexcept(false)
		{
#pragma warning(push)
#pragma warning(disable : 4996) // FIXME - deprecated function
			m_GuardedMutex = static_cast<PKGUARDED_MUTEX>(
				ExAllocatePoolWithTag(NonPagedPoolNx,
					sizeof(*m_GuardedMutex),
					PoolTag));
#pragma warning(pop)
			if (!m_GuardedMutex)
				terminate();

			KeInitializeGuardedMutex(m_GuardedMutex);
		}

		~mutex() noexcept
		{
			if (m_GuardedMutex)
			{
				ExFreePoolWithTag(m_GuardedMutex, PoolTag);
			}
		}

		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		void lock() noexcept
		{
			KeAcquireGuardedMutex(m_GuardedMutex);
		}

		bool tryLock() noexcept
		{
			return (KeTryToAcquireGuardedMutex(m_GuardedMutex) != FALSE ? true : false);
		}

		void unlock() noexcept
		{
			KeReleaseGuardedMutex(m_GuardedMutex);
		}

		native_handle_type native_handle() noexcept
		{
			return m_GuardedMutex;
		}

	private:

		PKGUARDED_MUTEX m_GuardedMutex = nullptr;

	};

	template <ULONG PoolTag>
	class mutex<LockStrategy::ResourceLock, PoolTag>
	{
	public:
		using native_handle_type = PERESOURCE;

		mutex() noexcept(false)
		{
			m_mutex = static_cast<PERESOURCE>(
				ExAllocatePoolWithTag(mutex_pool_type, sizeof(ERESOURCE), mutex_pool_tag)
				);

			if (!m_mutex)
				return;

			[[maybe_unused]] auto status = ::ExInitializeResourceLite(m_mutex);
			NT_ASSERT(status == STATUS_SUCCESS);
		}

		~mutex() noexcept
		{
			if (m_mutex)
			{
				::ExDeleteResourceLite(m_mutex);
				::ExFreePoolWithTag(m_mutex, mutex_pool_tag);

				m_mutex = nullptr;
			}
		}

		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		void lock() noexcept
		{
			::ExAcquireResourceExclusiveLite(m_mutex, TRUE);
		}

		bool tryLock() noexcept
		{
			return static_cast<bool>(
				::ExAcquireResourceExclusiveLite(m_mutex, FALSE)
				);
		}

		void lock_shared()
		{
			ExAcquireResourceSharedLite(m_mutex, TRUE);
		}

		bool try_lock_shared()
		{
			return static_cast<bool>(
				::ExAcquireResourceSharedLite(m_mutex, FALSE));
		}

		void unlock_shared()
		{
			::ExReleaseResourceLite(m_mutex);
		}

		void unlock() noexcept
		{
			::ExReleaseResourceLite(m_mutex);
		}

		native_handle_type native_handle() noexcept
		{
			return m_mutex;
		}

	private:
		PERESOURCE m_mutex{};
	};

	template <ULONG PoolTag>
	class mutex<LockStrategy::SpinLock, PoolTag>
	{
	public:
		using native_handle_type = PKSPIN_LOCK;

		mutex() noexcept(false)
		{
			m_mutex = static_cast<PKSPIN_LOCK>(
				::ExAllocatePoolWithTag(mutex_pool_type, sizeof(KSPIN_LOCK), PoolTag)
				);

			if (!m_mutex)
			{
				return;
			}

			::KeInitializeSpinLock(m_mutex);
		}

		~mutex()
		{
			if (m_mutex)
			{
				::ExFreePoolWithTag(m_mutex, PoolTag);
				m_mutex = nullptr;
			}
		}

		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		void lock() noexcept
		{
			KeAcquireSpinLock(m_mutex, &m_irql);
		}

		constexpr bool tryLock() noexcept(false)
		{
			throw std::runtime_error("method try_lock() for a spinlock mutex is not implemented");
		}

		void unlock() noexcept
		{
			::KeReleaseSpinLock(m_mutex, m_irql);
		}

		native_handle_type native_handle() noexcept
		{
			return m_mutex;
		}

	private:
		KIRQL m_irql;
		PKSPIN_LOCK m_mutex;
	};

	template <ULONG PoolTag>
	class mutex<LockStrategy::InStackQueueSpinLock, PoolTag>
	{
	public:
		using native_handle_type = PKSPIN_LOCK;

		mutex() noexcept(false)
		{
			m_mutex = static_cast<PKSPIN_LOCK>(
				::ExAllocatePoolWithTag(mutex_pool_type, sizeof(KSPIN_LOCK), PoolTag)
				);

			m_hLock = reinterpret_cast<PKLOCK_QUEUE_HANDLE>(
				::ExAllocatePoolWithTag(mutex_pool_type, sizeof(KLOCK_QUEUE_HANDLE), PoolTag)
				);

			if (!m_mutex || !m_hLock)
			{
				::terminate();
			}

			::KeInitializeSpinLock(m_mutex);
		}

		~mutex()
		{
			if (m_mutex)
			{
				::ExFreePoolWithTag(m_mutex, PoolTag);
				m_mutex = nullptr;
			}
			
			if (m_hLock)
			{
				::ExFreePoolWithTag(m_hLock, PoolTag);
				m_hLock = nullptr;
			}
		}

		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		void lock() noexcept
		{
			KeAcquireInStackQueuedSpinLock(m_mutex, m_hLock);
		}

		constexpr bool tryLock() noexcept(false)
		{
			throw std::runtime_error("method try_lock() for a InStackQueueSpinLock mutex is not implemented");
		}

		void unlock() noexcept
		{
			::KeReleaseInStackQueuedSpinLock(m_hLock);
		}

		native_handle_type native_handle() noexcept
		{
			return m_mutex;
		}

	private:
		PKLOCK_QUEUE_HANDLE	m_hLock;
		PKSPIN_LOCK			m_mutex;
	};

	// type alias
	using fast_mutex					= mutex<LockStrategy::FastMutex>;
	using guarded_mutex					= mutex<LockStrategy::GuardedMutex>;
	using resource_mutex				= mutex<LockStrategy::ResourceLock>;
	using spinlock_mutex				= mutex<LockStrategy::SpinLock>;
	using InStackQueueSpinLock_mutex	= mutex<LockStrategy::InStackQueueSpinLock>;


	// openedr(https://github.com/ComodoSecurity/openedr)
	template<typename Mutex>
	class UniqueLock
	{
		Mutex& m_mtx;
		bool m_fOwnLock = false;
	public:
		UniqueLock(Mutex& mtx) :m_mtx(mtx)
		{
			lock();
		}

		~UniqueLock()
		{
			unlock();
		}

		void lock()
		{
			m_mtx.lock();
			m_fOwnLock = true;
		}

		bool tryLock()
		{
			if (m_fOwnLock)
			{
				return true;
			}
			m_fOwnLock = m_mtx.tryLock();
			return m_fOwnLock;
		}

		void unlock()
		{
			m_mtx.unlock();
			m_fOwnLock = false;
		}

		bool hasLock() const
		{
			return m_fOwnLock;
		}

		operator bool() const
		{
			return hasLock();
		}
	};

}

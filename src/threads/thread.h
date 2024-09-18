#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/fixed-point.h"
#include "threads/synch.h"
#include "filesys/file.h"
/** States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /**< Running thread. */
    THREAD_READY,       /**< Not running but ready to run. */
    THREAD_BLOCKED,     /**< Waiting for an event to trigger. */
    THREAD_DYING        /**< About to be destroyed. */
  };

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0                       /**< Lowest priority. */
#define PRI_DEFAULT 31                  /**< Default priority. */
#define PRI_MAX 63                      /**< Highest priority. */

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /**< Thread identifier. */
    enum thread_status status;          /**< Thread state. */
    char name[16];                      /**< Name (for debugging purposes). */
    uint8_t *stack;                     /**< Saved stack pointer. */
    int priority;                       /**< Priority. */
    int base_priority;                  /**< 接受捐献时存储原来的优先级 */
    struct list_elem allelem;           /**< List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /**< List element. */
    struct list lock_list;              /**< 当前线程持有的锁的list */
    struct lock* lock_waiting;          /**< 当前线程等待的锁 */
    int donation;                       /**< 接受的最高的donation */
    int nice;                           /**< nice for mlfqs */
    fp recent_cpu;                      /**< recent cpu for mlfqs */
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /**< Page directory. */
    int exit_code;                      /**< exit code */
    struct list child_list;             /**< list of child */
    struct comm_with_parent* cwp;       /**< 父子进程互相交流信息的struct, 
                                             如果从来没有过父进程，为NULL。
                                             父进程死的时候清理子进程的cwp
                                             没有父进程的进程死的时候自己清理 */
    struct semaphore sema_execute;      /**< 用于process execute的semaphore */
    bool start_process_success;         /**< 子进程是否成功在start_process中load */
    bool starting_process;              /**< 告诉thread_create是不是在
                                             starting process */
    struct lock cwp_lock;               /**< 保护cwp */
    struct file* executable;            /**< 自己的executable file */
    struct list file_list;              /**< 打开的文件列表 */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /**< Detects stack overflow. */
  };

/** userprog中子进程用于和父进程交流的struct */
struct comm_with_parent 
  {
    tid_t tid;                          /**< 子进程tid */
    struct thread* t;                   /**< 子进程struct thread，
                                             死亡时设为NULL */
    struct thread* parent;              /**< 父进程struct thread */
    int exit_code;                      /**< 子进程exit code */
    struct semaphore sema_wait;         /**< 用于wait的semaphore */
    struct list_elem elem;              /**< 用于插入父进程的child_list */
  };

/** 进程的文件 */
struct file_list_entry
  {
    int fd;                             /**< 文件描述符 */
    struct file* f;                     /**< file 结构指针 */
    struct list_elem elem;              /**< 用于插入线程的file_list */
  };


/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

struct list ready_list;
struct list all_list;
/* 保护cwp系统 */
struct lock cwp_lock; 
/* filesys lock */
struct lock filesys_lock;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

bool thread_priority_great(const struct list_elem *left, 
                           const struct list_elem *right, 
                           void* aux);
#endif /**< threads/thread.h */

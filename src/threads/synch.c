/** This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/** Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static bool sema_priority_great(const struct list_elem *left, 
                                const struct list_elem *right, 
                                void* aux UNUSED);
bool lock_priority_great(const struct list_elem *left, 
                         const struct list_elem* right, 
                         void *aux UNUSED);

/** Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/** Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      list_insert_ordered(&sema->waiters, &thread_current ()->elem,
                           thread_priority_great, NULL);
      thread_block ();
    }
  sema->value--;
  intr_set_level (old_level);
}

/** Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/** Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)) 
  {
    list_sort(&sema->waiters, thread_priority_great, NULL);
    thread_unblock (list_entry (list_pop_front (&sema->waiters), 
                    struct thread, elem));
  }
  sema->value++;

  if (intr_context())
  {
    intr_yield_on_return();
  }
  
  intr_set_level (old_level);
  // 不加这个yield，priority-sema过不了，不加INTR_ON，alarm_multiple过不了
#ifndef VM
  if(!intr_context() && old_level == INTR_ON)
  {
    thread_yield();
  }
#endif
}

static void sema_test_helper (void *sema_);

/** Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/** Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/** Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
  lock->priority = PRI_MIN;
}

bool lock_priority_great(const struct list_elem *left, 
                         const struct list_elem* right, 
                         void *aux UNUSED)
{
  return list_entry(left, struct lock, elem)->priority >
         list_entry(right, struct lock, elem)->priority;
}

/** Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  struct thread* t = thread_current();
  enum intr_level old_level;
  old_level = intr_disable (); 
  // mlfqs不需要donate
  if (!thread_mlfqs)
  {
    // 检查lock是否被别人持有，持有的话进行donate。此过程和sema_down需要保持原子性
    t->lock_waiting = lock;
    if (lock->holder != NULL && lock != NULL)
    {
      
      lock->priority = t->priority > lock->priority ?
                       t->priority : lock->priority;
      lock->holder->priority = t->priority > lock->holder->priority ?
                               t->priority : lock->holder->priority;
      lock->holder->donation = t->priority > lock->holder->donation ?
                               t->priority : lock->holder->donation;
      //donate chain
      int count = 8;
      struct thread* thread_iter = lock->holder;
      struct lock* lock_iter = thread_iter->lock_waiting;
      while (is_thread(thread_iter) && 
             lock_iter != NULL && 
             count > 0 && 
             lock_iter->holder != NULL)
      {
        lock_iter->priority = thread_iter->priority > 
          lock_iter->priority ? 
            thread_iter->priority : lock_iter->priority;
        lock_iter->holder->priority = thread_iter->priority > 
            lock_iter->holder->priority ? 
              thread_iter->priority : lock_iter->holder->priority;

        lock_iter->holder->donation = thread_iter->priority > 
          lock_iter->holder->donation ? 
            thread_iter->priority : lock_iter->holder->donation;

        count--;
        thread_iter = lock_iter->holder;
        lock_iter = thread_iter->lock_waiting;
      }
    }
  }


  sema_down (&lock->semaphore);

  // mlfqs不需要donate
  if (!thread_mlfqs)
  {
    // 获得锁了，lock->priority是指在wait中的线程的最大priority，
    // 故需要对lock的priority进行修改
    if (!list_empty(&(lock->semaphore.waiters)))
    {
      // 有别人在等锁，lock->priority设置成
      // lock->semaphore.waiters里的线程中最高的priority
      list_sort(&(lock->semaphore.waiters), thread_priority_great, NULL);
      lock->priority = (list_entry (list_front(&(lock->semaphore.waiters)), 
                      struct thread, elem))->priority;
    }
    else
    {
      // 锁没人用了，但是为了下次使用需要重置priority
      lock->priority = PRI_MIN;
    }
    t->lock_waiting = NULL;
    // 标记为持有
    list_insert_ordered(&t->lock_list, &lock->elem, 
                        lock_priority_great, NULL);
    
  }
  lock->holder = thread_current ();
  intr_set_level (old_level);
  
}

/** Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/** Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  struct thread* t = thread_current();
  if (!thread_mlfqs)
  {
    
    // 从线程的lock_list移除
    list_remove(&lock->elem);
    // 改变t->donation
    if (!list_empty(&t->lock_list))
    {
      list_sort(&(t->lock_list), lock_priority_great, NULL);
      t->donation = (list_entry (list_front(&t->lock_list), 
                    struct lock, elem))->priority;
    }
    else
    {
      // 不持有锁了，donation重置
      t->donation = PRI_MIN;
    }
    
  }
  lock->holder = NULL;
  sema_up (&lock->semaphore);
  if (!thread_mlfqs)
  {
    thread_set_priority(t->base_priority);
  }

}

/** Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/** One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /**< List element. */
    struct semaphore semaphore;         /**< This semaphore. */
    /* 在condv的wait中，会为每个线程创建一个semaphore_elem，
    并插入condv的waitlist中，故在此需要priority来比较不同优
    先级的等待线程，以便按优先级插入 */
    int priority; 
  };

/** Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/** Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  waiter.priority = thread_get_priority();
  list_insert_ordered(&cond->waiters, &waiter.elem, 
                      sema_priority_great, NULL);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);

}

/* 比较两个sema的优先级 */
static bool sema_priority_great(const struct list_elem *left, 
                                const struct list_elem *right, 
                                void* aux UNUSED)
{
  return list_entry(left, struct semaphore_elem, elem)->priority >
         list_entry(right, struct semaphore_elem, elem)->priority;
}

/** If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters)) {
    list_sort(&cond->waiters,sema_priority_great, NULL);
    sema_up (&list_entry (list_pop_front (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
  }
}

/** Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}

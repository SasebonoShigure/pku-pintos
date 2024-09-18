#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include <string.h>
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "devices/input.h"

static void sys_halt(void);
static void sys_exit(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_exec(struct intr_frame *f);
static void sys_wait(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_close(struct intr_frame *f);
static void sys_filesize(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_seek(struct intr_frame *f);
static void sys_tell(struct intr_frame *f);



static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static inline void check_read(void* _p, size_t size);
static inline void check_write(void* p, size_t size);
static inline void check_read_str(char* p);




void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  check_read(f->esp, sizeof(int));
  int syscall_num = *(int *)f->esp;
  switch (syscall_num)
  {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit(f);
      break;
    case SYS_WRITE:
      sys_write(f);
      break;
    case SYS_EXEC:
      sys_exec(f);
      break;
    case SYS_WAIT:
      sys_wait(f);
      break;
    case SYS_CREATE:
      sys_create(f);
      break;
    case SYS_REMOVE:
      sys_remove(f);
      break;
    case SYS_OPEN:
      sys_open(f);
      break;
    case SYS_CLOSE:
      sys_close(f);
      break;
    case SYS_FILESIZE:
      sys_filesize(f);
      break;
    case SYS_READ:
      sys_read(f);
      break;
    case SYS_SEEK:
      sys_seek(f);
      break;
    case SYS_TELL:
      sys_tell(f);
      break;
    default:
      PANIC("invalid syscall");
      break;
  }
}

static inline void sys_halt()
{
  shutdown_power_off();
}

static void sys_exit(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  thread_current()->exit_code = *(int *)(f->esp + sizeof(uint32_t));
  thread_exit();
}

static void sys_write(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  check_read(f->esp + 2 * sizeof(uint32_t),sizeof(char*));
  char* buf = *(char **)(f->esp + 2 * sizeof(uint32_t));
  check_read_str(buf);
  check_read(f->esp + 3 * sizeof(uint32_t), sizeof(int));
  int size = *(int *)(f->esp + 3 * sizeof(uint32_t));
  if (fd == 1)
  {
    putbuf(buf, size);
    f->eax = size;
  }
  else
  {
    struct file_list_entry* fle = fd_to_fle(fd);
    if (fle != NULL) {
      lock_acquire(&filesys_lock);
      f->eax = file_write(fle->f, buf, size);
      lock_release(&filesys_lock);
    }
    else
    {
      f->eax = -1;
    }
  }
}

static void sys_exec(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(char*));
  char* cmd = *(char **)(f->esp + sizeof(uint32_t));
  check_read_str(cmd);
  f->eax = process_execute(cmd);
}

static void sys_wait(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int pid = *(int *)(f->esp + sizeof(uint32_t));
  f->eax = process_wait(pid);
}

static void sys_create(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(char*));
  char* file_name = *(char **)(f->esp + sizeof(uint32_t));
  check_read_str(file_name);
  check_read(f->esp + 2 * sizeof(uint32_t), sizeof(unsigned));
  unsigned size = *(unsigned*)(f->esp + 2 * sizeof(uint32_t));
  lock_acquire(&filesys_lock);
  f->eax = filesys_create(file_name, size);
  lock_release(&filesys_lock);
}

static void sys_remove(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(char*));
  char* file_name = *(char **)(f->esp + sizeof(uint32_t));
  check_read_str(file_name);
  lock_acquire(&filesys_lock);
  f->eax = filesys_remove(file_name);
  lock_release(&filesys_lock);
}

static void sys_open(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(char*));
  char* file_name = *(char **)(f->esp + sizeof(uint32_t));
  check_read_str(file_name);
  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(file_name);
  lock_release(&filesys_lock);

  if (file != NULL)
  {
    struct thread* t = thread_current();
    struct file_list_entry* fle = (struct file_list_entry*)
                                  malloc(sizeof(struct file_list_entry));
    fle->fd = get_new_fd();
    fle->f = file;
    list_insert_ordered(&t->file_list, &fle->elem, fd_less, NULL);
    f->eax = fle->fd;
  }
  else
  {
    // 打开失败
    f->eax = -1;
  }
}

static void sys_close(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  struct file_list_entry* fle = fd_to_fle(fd);
  if (fle != NULL)
  {
    lock_acquire(&filesys_lock);
    file_close(fle->f);
    lock_release(&filesys_lock);
    list_remove(&fle->elem);
    free(fle);
  }
}

static void sys_filesize(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  struct file_list_entry* fle = fd_to_fle(fd);
  if (fle != NULL)
  {
    lock_acquire(&filesys_lock);
    f->eax = file_length(fle->f);
    lock_release(&filesys_lock);
  }
  else
  {
    f->eax = -1;
  }
}

static void sys_read(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  check_read(f->esp + 2 * sizeof(uint32_t),sizeof(char*));
  char* buf = *(char **)(f->esp + 2 * sizeof(uint32_t));
  check_read(f->esp + 3 * sizeof(uint32_t), sizeof(int));
  unsigned size = *(int *)(f->esp + 3 * sizeof(uint32_t));
  if (size == 0)
  {
    f->eax = 0;
  }
  else
  {
    // size是0的时候不用check_write，直接返回0就行
    check_write(buf, size);
    if (fd == 0)
    {
      for (size_t i = 0; i < size; i++)
      {
        *buf = (char)input_getc();
        buf++;
      }
      f->eax = size;
    }
    else
    {
      struct file_list_entry* fle = fd_to_fle(fd);
      if (fle != NULL)
      {
        lock_acquire(&filesys_lock);
        f->eax = file_read(fle->f, buf, size);
        lock_release(&filesys_lock);
      }
      else
      {
        f->eax = -1;
      }
    }
  }
}

static void sys_seek(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  check_read(f->esp + 2 * sizeof(uint32_t), sizeof(unsigned));
  unsigned position = *(int *)(f->esp + 2 * sizeof(uint32_t));
  struct file_list_entry* fle = fd_to_fle(fd);
  if (fle != NULL)
  {
    lock_acquire(&filesys_lock);
    file_seek(fle->f, position);
    lock_release(&filesys_lock);
  }
}

static void sys_tell(struct intr_frame *f)
{
  check_read(f->esp + sizeof(uint32_t), sizeof(int));
  int fd = *(int *)(f->esp + sizeof(uint32_t));
  struct file_list_entry* fle = fd_to_fle(fd);
  if (fle != NULL)
  {
    lock_acquire(&filesys_lock);
    f->eax = file_tell(fle->f);
    lock_release(&filesys_lock);
  }
  else
  {
    f->eax = -1;
  }
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* 检查从_p读取size字节是否合法 */
static inline void check_read(void* p, size_t size)
{
  if (size == 0)
  {
    // 避免下面循环出问题
    return;
  }
  // 检查开头在不在user space
  if (!is_user_vaddr(p))
  {
    thread_current()->exit_code = -1;
    thread_exit();
    NOT_REACHED();
  }
  void* _p = p;
  uint32_t max_page = (uint32_t)pg_round_down(p);
  for(;; p = p + PGSIZE > _p + size - 1 ? _p + size - 1 : p + PGSIZE)
  {
    if ((uint32_t)pg_round_down(p) <= max_page)
    {
      // 新的一页了，需要检查
      max_page += PGSIZE;
      if (!is_user_vaddr(p))
      {
        thread_current()->exit_code = -1;
        thread_exit();
        NOT_REACHED();
      }
      else
      {
        if (get_user((const uint8_t *)(p)) == -1)
        {
          thread_current()->exit_code = -1;
          thread_exit();
          NOT_REACHED();
        }
      }
    }
    if (p == _p + size -1)
    {
      break;
    }
  }
}

/* 检查向_p写入size字节是否合法 */
static inline void check_write(void* p, size_t size)
{
  // 检查地址是否在user space
  if (!is_user_vaddr(p))
  {
    thread_current()->exit_code = -1;
    thread_exit();
    NOT_REACHED();
  }
  // 用put_user检查写入合法性
  if (!put_user(p, size))
  {
    thread_current()->exit_code = -1;
    thread_exit();
    NOT_REACHED();
  }
}

/* 检查从_p读取字符串是否合法 */
static inline void check_read_str(char* p)
{
  // 检查开头在不在user space
  if (!is_user_vaddr(p))
  {
    thread_current()->exit_code = -1;
    thread_exit();
    NOT_REACHED();
  }
  uint32_t max_page = (uint32_t)pg_round_down(p);
  for(;;p++)
  {
    if ((uint32_t)pg_round_down(p) <= max_page)
    {
      // 新的一页了，需要检查
      max_page += PGSIZE;
      if (!is_user_vaddr(p))
      {
        thread_current()->exit_code = -1;
        thread_exit();
        NOT_REACHED();
      }
      else
      {
        if (get_user((const uint8_t *)(p)) == -1)
        {
          thread_current()->exit_code = -1;
          thread_exit();
          NOT_REACHED();
        }
      }
    }
    if (*p == '\0')
    {
      break;
    }
  }
}
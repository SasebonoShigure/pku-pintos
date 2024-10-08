#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
bool fd_less(const struct list_elem *left, 
             const struct list_elem *right, 
             void* aux);

int get_new_fd(void);
struct file_list_entry* fd_to_fle(int fd);

/* 为进程死亡做准备 */
void process_funeral()
{
  struct thread* t = thread_current();
  // 处理child_list的cwp
  struct list_elem *e;
  struct list_elem *enext;
  struct comm_with_parent* cwp;

  lock_acquire(&cwp_lock);
  e = list_begin(&t->child_list);
  while (e != list_end(&t->child_list))
  {
    enext = list_next(e);
    cwp = list_entry(e, struct comm_with_parent, elem);
    // 子进程还活着，要把它的cwp设为NULL
    if (cwp->t != NULL)
    {
      cwp->t->cwp = NULL;
    }
    free(cwp);
    e = enext;
  }
  lock_release(&cwp_lock);

  // 处理自己的cwp
  lock_acquire(&cwp_lock);
  // 父进程还在
  if (t->cwp != NULL)
  {
    ASSERT (t->cwp->parent != NULL);
    t->cwp->t = NULL;
    t->cwp->exit_code = t->exit_code;
    sema_up(&t->cwp->sema_wait);
  }
  else
  {
    // 父进程死了
    free(t->cwp);
  }
  lock_release(&cwp_lock);
  // 关闭所有文件
  struct file_list_entry* fle;
  int fd;
  while(!list_empty(&t->file_list))
  {
    fd = list_entry(list_front(&t->file_list), 
                    struct file_list_entry, elem)->fd;
    fle = fd_to_fle(fd);
    if (fle != NULL)
    {
      lock_acquire(&filesys_lock);
      file_close(fle->f);
      lock_release(&filesys_lock);
      list_remove(&fle->elem);
      free(fle);
    }
  }
  // 关掉自己的executable
  lock_acquire(&filesys_lock);
  file_close(t->executable);
  lock_release(&filesys_lock);
#ifdef VM
  lock_acquire(&filesys_lock);
  file_close(t->VM_executable);
  lock_release(&filesys_lock);
  lock_acquire(&frame_lock);
  hash_destroy(t->supplemental_page_table, spte_destroy_func);
  lock_release(&frame_lock);
  free(t->supplemental_page_table);
#endif
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = (char*)malloc(strlen(file_name) + 1);
  if (fn_copy == NULL)
    return TID_ERROR;

  strlcpy (fn_copy, file_name, PGSIZE);
  char* file_name_copy = (char*)malloc(strlen(file_name) + 1);
  ASSERT (file_name_copy != NULL);
  strlcpy (file_name_copy, file_name, PGSIZE);
  char *save_ptr;
  char *file_name_without_arg = strtok_r(file_name_copy, " ", &save_ptr);
  struct thread* t = thread_current();
  sema_init(&t->sema_execute, 0);
  t->starting_process = true;
  t->start_process_success = false;
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name_without_arg, PRI_DEFAULT, 
                       start_process, fn_copy);
  free(file_name_copy);
  if (tid == TID_ERROR)
  {
    free(fn_copy); 
  }
  else 
  {
    // 小心死锁，如果thread_create失败，sema_up不会被调用
    sema_down(&t->sema_execute);
  }

  if (!t->start_process_success) 
  {
    tid = -1;
  }
  t->starting_process = false;
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  char *save_ptr;
  // 由于file_name由start_process来free，因此可以随意更改
  char *arg = strtok_r(file_name, " ", &save_ptr);
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (arg, &if_.eip, &if_.esp);
  struct thread* t = thread_current();
  // 在这里访问cwp的时候父进程被block住，不需要cwp_lock
  struct thread* parent = t->cwp->parent;
  /* If load failed, quit. */
  if (!success) 
  {
    // free移到if里面，因为success的时候后面还有用
    // thread_exit NORETURN，注意顺序
    free(file_name);
    sema_up(&parent->sema_execute);
    thread_current()->exit_code = -1;

    thread_exit ();
    NOT_REACHED ();
  }
  // success

  parent->start_process_success = true;
  sema_up(&parent->sema_execute);
  // 拒绝写入executable的相关操作
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(arg);
  file_deny_write(f);
  lock_release(&filesys_lock);
  thread_current()->executable = f;
  /* 处理栈 */
  if_.esp = PHYS_BASE;
  int argc = 0;
  char* argv[66]; // 命令行参数最大128 byte，argv数量最多是65
  for (; arg != NULL; arg = strtok_r (NULL, " ", &save_ptr))
  {
    argv[argc] = arg;
    argc++;
  }
  /* argv[i][...] */
  for (int i = argc - 1; i >= 0; i--)
  {
    size_t len = strlen(argv[i]) + 1;
    if_.esp -= len;
    strlcpy(if_.esp, argv[i], len);
    argv[i] = if_.esp;
  }
  /* word-align */
  size_t round = (uint32_t)(if_.esp) % 4;
  if_.esp -= round;
  memset(if_.esp, 0, round);
  /* null pointer sentinel */
  if_.esp -= sizeof(char*);
  memset(if_.esp, 0, sizeof(char*));
  /* argv[i] */
  for (int i = argc - 1; i >= 0; i--)
  {
    if_.esp -= sizeof(char*);
    *((char**)(if_.esp)) = argv[i];
  }
  /* argv */
  if_.esp -= sizeof(char*);
  *(char***)if_.esp = (char**)(if_.esp + 4);
  /* argc */
  if_.esp -= sizeof(int);
  *((int*)(if_.esp)) = argc;
  /* return address */
  if_.esp -= sizeof(uint32_t);
  *(uint32_t*)(if_.esp) = 0;


  free(file_name);
# ifdef VM
  // 推迟到这里release是在内核态的时候用户栈不能被swap out
  // 做一次判断，偷个懒，因为load中goto太乱了。。
  if (lock_held_by_current_thread(&frame_lock))
  {
    lock_release(&frame_lock);
  }
  
#endif
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread* t = thread_current();
  struct list_elem *e;
  struct comm_with_parent* cwp;
  int return_code = -1;
  for (e = list_begin (&t->child_list); e != list_end (&t->child_list); 
                       e = list_next (e))
  {
    cwp = list_entry(e, struct comm_with_parent, elem);
    if (cwp->tid == child_tid)
    {
      if (cwp->t == NULL)
      {
        // 子进程死了
        return_code = cwp->exit_code;
        list_remove(e);
        free(cwp);
        break;
      }
      else
      {
        // 没死，等待
        sema_down(&cwp->sema_wait);
        return_code = cwp->exit_code;
        list_remove(e);
        free(cwp);
        break;
      }
      
    }
  }
  return return_code;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  printf ("%s: exit(%d)\n", cur->name,cur->exit_code);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open (file_name);
  lock_release(&filesys_lock);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  /* Read and verify executable header. */
  lock_acquire(&filesys_lock);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release(&filesys_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  lock_release(&filesys_lock);
  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      lock_acquire(&filesys_lock);
      file_seek (file, file_ofs);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
      {
        lock_release(&filesys_lock);
        goto done;
      }
      lock_release(&filesys_lock);
      
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              

              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
#ifdef VM
  // lazy load 还要用到file，不close
  // 需要在进程退出时关闭
  thread_current()->VM_executable = file;
#else
  lock_acquire(&filesys_lock);
  file_close (file);
  lock_release(&filesys_lock);
#endif
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  lock_acquire(&filesys_lock);
  if (phdr->p_offset > (Elf32_Off) file_length (file))
  {
    lock_release(&filesys_lock);
    return false;
  }
  lock_release(&filesys_lock);
  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  lock_acquire(&filesys_lock);
  file_seek (file, ofs);
  lock_release(&filesys_lock);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
#ifdef VM
      // lazy load
      struct supplemental_page_table_entry *spte;
      spte = (struct supplemental_page_table_entry*)
             malloc(sizeof(struct supplemental_page_table_entry));

      spte->upage = upage;
      spte->status = LAZY_LOAD;
      spte->file = file;
      spte->offset = ofs;
      spte->read_bytes = page_read_bytes;
      spte->zero_bytes = page_zero_bytes;
      spte->writable = writable;
      spte->kpage = NULL;
      if (hash_insert (thread_current()->supplemental_page_table, 
                       &spte->elem))
      {
        PANIC("spt already has entry in load_segment");
      }

      ofs += PGSIZE;
#else
      /* Get a page of memory. */
      uint8_t *kpage = get_frame (PAL_USER, upage);
      if (kpage == NULL)
      {
        return false;
      }
        
      lock_acquire(&filesys_lock);
      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          lock_release(&filesys_lock);
          free_frame (kpage);
          return false; 
        }
      lock_release(&filesys_lock);
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          free_frame (kpage);
          return false; 
        }

#endif
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }

  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;
# ifdef VM
  lock_acquire(&frame_lock);
#endif
  kpage = get_frame (PAL_USER | PAL_ZERO, ((uint8_t *) PHYS_BASE) - PGSIZE);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;
      }
      else
        free_frame (kpage);
    }
# ifdef VM
  pagedir_set_dirty(thread_current()->pagedir, kpage, true);
#endif
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. 
   同时负责向spt插入条目 */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool flag = (pagedir_get_page (t->pagedir, upage) == NULL
              && pagedir_set_page (t->pagedir, upage, kpage, writable));
#ifdef VM
  flag = flag && spt_add_page(t, upage, IN_USE, kpage);
#endif
  return flag;
}


bool fd_less(const struct list_elem *left, 
             const struct list_elem *right, 
             void* aux UNUSED)
{
  return list_entry(left, struct file_list_entry, elem)->fd < 
         list_entry(right, struct file_list_entry, elem)->fd;
}

/** 返回新fd */
int get_new_fd(void)
{
  struct thread* t = thread_current();
  // 01被保留
  if (list_empty(&t->file_list))
  {
    return 2;
  }
  else
  {
    struct file_list_entry* fle = list_entry(list_back(&t->file_list), 
                                             struct file_list_entry, 
                                             elem);
    return fle->fd + 1;
  }
}

struct file_list_entry* fd_to_fle(int fd)
{
  struct thread* t = thread_current();
  struct file_list_entry* ret = NULL;
  struct file_list_entry* fle;
  for (struct list_elem* e = list_begin (&t->file_list); 
                                         e != list_end (&t->file_list); 
                                         e = list_next(e))
  {
    fle = list_entry(e,struct file_list_entry, elem);
    if (fle->fd == fd)
    {
      ret = fle;
      break;
    }
  }
  return ret;
}

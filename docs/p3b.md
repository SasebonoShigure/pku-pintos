# Project 3b: Virtual Memory

## Preliminaries

>Fill in your name and email address.



>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Stack Growth

#### ALGORITHMS

>A1: Explain your heuristic for deciding whether a page fault for an
>invalid virtual address should cause the stack to be extended into
>the page that faulted.

- 满足以下条件才需要`stack growth`：
  1. 不是向只读页写入
  2. `SPT`没有此条目
  3. `fault address`在`PHYS_BASE`下面
  4. `fault address`不小于`PHYS_BASE - MAX_STACK_SIZE`
  5. `fault address`在用户栈指针附近

## Memory Mapped Files

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```C
typedef int mmapid;

struct mmap_list_entry {
    mmapid id;                     /**< 进程的mmap id */
    struct list_elem elem;         /**< 用于插入进程的mmap list */
    struct file* file;             /**< file指针 */
    size_t size;                   /**< 文件大小 */
    void *upage;                   /**< 起始的用户地址 */
  };

  struct thread
  {
    ...
#ifdef VM
    ...
    struct list mmap_list;               /**< mmap文件的list */
#endif
    ...
  };

```

#### ALGORITHMS

>B2: Describe how memory mapped files integrate into your virtual
>memory subsystem.  Explain how the page fault and eviction
>processes differ between swap pages and other pages.

- `mmap`的时候会添加一系列`LAZY_LOAD`的页的条目进`SPT`，后面访问的时候遇到`page fault`再从文件读取。`munmap`的时候会根据是否`dirty`来决定是写回文件还是直接释放页。
- `swap page`在`swap in`的时候要手动设置`dirty`为`true`。另外，在`evict`的时候只有`dirty`的页会`swap`出去，干净的可以直接释放。`page fault`的时候，`swap page`从`swap slot`里读取，而`DEMAND_ZERO`分配全`0`页就可以，`LAZY_LOAD`的页从文件读取。

>B3: Explain how you determine whether a new file mapping overlaps
>any existing segment.

- `mmap`的时候会添加一系列`LAZY_LOAD`的页的条目进`SPT`，而向`SPT`插入已有条目会`PANIC`，保证了不会`overlap`。

#### RATIONALE

>B4: Mappings created with "mmap" have similar semantics to those of
>data demand-paged from executables, except that "mmap" mappings are
>written back to their original files, not to swap.  This implies
>that much of their implementation can be shared.  Explain why your
>implementation either does or does not share much of the code for
>the two situations.

- 我的实现在两种情况下用的是同一套代码，好处是统一，便于管理，而且二者行为确实很接近，只需要在原来基础上做小改动就可以实现`mmap`。

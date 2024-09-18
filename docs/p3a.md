# Project 3a: Virtual Memory

## Preliminaries

>Fill in your name and email address.



>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Page Table Management

#### DATA STRUCTURES

>A1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```C

enum page_status {
    IN_USE,                        /**< 在栈上 */
    SWAPPED_OUT,                   /**< 在swap slot里 */
    DEMAND_ZERO,                   /**< demand zero */
    LAZY_LOAD                      /**< lazy load */
  };

struct frame_hash_table_entry
  {
    struct thread* t;              /**< 物理页所属的进程 */
    void* kpage;                   /**< kernel address */
    struct hash_elem elem;         /**< 插入frame_hash_table */
    void* upage;                   /**< user kernel address */
  };

struct supplemental_page_table_entry
  {
    void* upage;                   /**< user kernel address */
    struct hash_elem elem;         /**< 插入supplemental_page_table */
    enum page_status status;       /**< 状态 */
    bool writable;                 /**< writable */
    void* kpage;                   /**< 不在内存中时为NULL */
  };

struct thread
  {
    ...
#ifdef VM
    struct hash* supplemental_page_table;/**< supplemental_page_table */
    uint8_t* esp;                        /**< 用户栈的esp，为了stack growth */
    struct file* VM_executable;          /**< 自己的executable file，
                                              用于lazy load */
    struct list mmap_list;               /**< mmap文件的list */
#endif
    ...
  };

/* frame相关数据结构的锁 */
struct lock frame_lock;
static struct hash frame_hash_table;

```

#### ALGORITHMS

>A2: In a few paragraphs, describe your code for accessing the data
>stored in the SPT about a given page.

- `SPT`通过`hash table`实现，每个进程有自己的`SPT`，`SPT`条目在`hash table`中由`user virtual address`索引，查询通过条目的`upage`成员实现。

>A3: How does your code coordinate accessed and dirty bits between
>kernel and user virtual addresses that alias a single frame, or
>alternatively how do you avoid the issue?

- `kernel`状态修改用户进程的页面时都会手动设置`pagedir`中的`dirty bit`，比如建立完用户栈、`swap in`的时候。`accessed bit`没做特别处理。

#### SYNCHRONIZATION

>A4: When two user processes both need a new frame at the same time,
>how are races avoided?

- 分配页、修改`frame table`、`SPT`的时候都要获取`frame_lock`。通过这个锁来避免竞争。

#### RATIONALE

>A5: Why did you choose the data structure(s) that you did for
>representing virtual-to-physical mappings?

- `frame table`和`SPT`都用`hash table`实现，优点是快，而且`pintos`的`hash`库提供了完整的接口。

## Paging To And From Disk

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```C
struct supplemental_page_table_entry
  {

    ...

    uint32_t swap_index;           /**< swap出去的时候的index，
                                        其他时候是INT32_MAX */
    struct file* file;             /**< lazy load来源的文件 */
    uint32_t offset;               /**< lazy load来源的文件的offset */
    uint32_t read_bytes;           /**< lazy load要读多少 */
    uint32_t zero_bytes;           /**< lazy load要填充多少0 */
  };

struct frame_hash_table_entry
  {
    
    ...

    struct list_elem celem;        /**< 用于插入clock_list */
  };

/* swap的bitmap和block的锁 */
static struct lock swap_lock;       /* 保护swap block */
static struct block *swap_block;
// 0空1非空
static struct bitmap *swap_bitmap;  /* 指示swap slot占用状态 */
static size_t swap_maxnum;          /* swap最大页数量 */

static struct list clock_list;      /* clock algorithm用的 */
static struct list_elem* clock_ptr; /* clock algorithm指针 */
```

#### ALGORITHMS

>B2: When a frame is required but none is free, some frame must be
>evicted.  Describe your code for choosing a frame to evict.

- `frame table`条目中有一个`celem`成员，用于插入`clock_list`。`clock list`用于挑选要`evict`的页。具体过程如下：
  
  1. 当没有物理页可供分配时，`get_frame()`会调用`page_daemon()`。后者通过`clock algorithm`来挑选要驱逐的页
  2. 选中页后先清除页所属的进程`P`的`pagedir`里的这一页，这样`P`就不再能访问它，`P`如果在稍后访问了这一页，会触发`page fault`重新激活这一页。
  3. 选中页后，如果是`dirty`的，就`swap out`，如果不`dirty`，直接释放页就可以了。
  

>B3: When a process P obtains a frame that was previously used by a
>process Q, how do you adjust the page table (and any other data
>structures) to reflect the frame Q no longer has?

- `Q`在不拥有这一个物理页的时候就会删除`frame table`中这一页的条目，也会从`Q`的`page table`中移除这一页。`P`在获取任何页的时候都能保证这一页现在已经没人用了。

#### SYNCHRONIZATION

>B5: Explain the basics of your VM synchronization design.  In
>particular, explain how it prevents deadlock.  (Refer to the
>textbook for an explanation of the necessary conditions for
>deadlock.)

- 所有`SPT`、`frame table`的操作都由`frame_lock`保护，这个锁也保证了`palloc`库、`frame table`、`SPT`、`pagedir`的同步性。
- 死锁的前提是锁的获取顺序有逆序。在我的设计中，锁的获取在全局有排序：`filesys_lock`、`frame_lock`、`swap_lock`。

>B6: A page fault in process P can cause another process Q's frame
>to be evicted.  How do you ensure that Q cannot access or modify
>the page during the eviction process?  How do you avoid a race
>between P evicting Q's frame and Q faulting the page back in?

- > How do you ensure that Q cannot access or modify
the page during the eviction process?
  - 在evict过程中第一件事就是从`Q`的`pagedir`移除这一页，`Q`就不能访问了。
- > How do you avoid a race between P evicting Q's frame and Q faulting the page back in?
  - `evict`过程是在持有`frame_lock`的时候进行的，`Q`如果访问这一页会`page fault`，在后者中又会获取`frame_lock`，因此`Q`会被卡住直到`evict`彻底完成，这样就解决了问题。
  


>B7: Suppose a page fault in process P causes a page to be read from
>the file system or swap.  How do you ensure that a second process Q
>cannot interfere by e.g. attempting to evict the frame while it is
>still being read in?

- `page fault`导致读取文件一定已经获取了`frame_lock`，而`evict`过程也需要获取这个锁，所以读取过程中不可能被`evict`。

>B8: Explain how you handle access to paged-out pages that occur
>during system calls.  Do you use page faults to bring in pages (as
>in user programs), or do you have a mechanism for "locking" frames
>into physical memory, or do you use some other design?  How do you
>gracefully handle attempted accesses to invalid virtual addresses?

- > Explain how you handle access to paged-out pages that occur during system calls.
  - `syscall`过程中遇到缺页也会触发`page fault`，调用`activate_page()`，会把缺的页激活，前提是地址合法，即`SPT`中有这个条目。
- > . Do you use page faults to bring in pages (as in user programs), or do you have a mechanism for "locking" frames into physical memory, or do you use some other design?
  - 我用`page fault`
- > How do you gracefully handle attempted accesses to invalid virtual addresses?
  - `page fault`会先调用`activate_page()`，尝试根据`SPT`激活这一页，如果失败，和之前一眼，如果是`kernel mode`导致的就返回`-1`，否则`kill`。

#### RATIONALE

>B9: A single lock for the whole VM system would make
>synchronization easy, but limit parallelism.  On the other hand,
>using many locks complicates synchronization and raises the
>possibility for deadlock but allows for high parallelism.  Explain
>where your design falls along this continuum and why you chose to
>design it this way.

- 我用一个锁来实现整个`VM`系统，对于pintos lab这种单核环境足够了，用一堆锁不会对性能有什么正面影响反而增加复杂度而且更容易导致bug。如果要推广到多核环境，才会考虑对此进行优化。

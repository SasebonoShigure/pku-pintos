#ifndef VM_PAGE_H
#define VM_PAGE_H
#ifdef VM
#include <hash.h>
#include "threads/palloc.h"
#include "threads/thread.h"
typedef int mmapid;
#define STACK_LIMIT 0x800000
/* 保护fht以及fht与spt的同步性 */
struct lock frame_lock;

struct mmap_list_entry {
    mmapid id;                     /**< 进程的mmap id */
    struct list_elem elem;         /**< 用于插入进程的mmap list */
    struct file* file;             /**< file指针 */
    size_t size;                   /**< 文件大小 */
    void *upage;                   /**< 起始的用户地址 */
  };

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
    struct list_elem celem;        /**< 用于插入clock_list */
  };

struct supplemental_page_table_entry
  {
    void* upage;                   /**< user kernel address */
    struct hash_elem elem;         /**< 插入supplemental_page_table */
    enum page_status status;       /**< 状态 */
    uint32_t swap_index;           /**< swap出去的时候的index，
                                        其他时候是INT32_MAX */
    bool writable;                 /**< writable */
    struct file* file;             /**< lazy load来源的文件 */
    uint32_t offset;               /**< lazy load来源的文件的offset */
    uint32_t read_bytes;           /**< lazy load要读多少 */
    uint32_t zero_bytes;           /**< lazy load要填充多少0 */
    void* kpage;                   /**< 不在内存中时为NULL */
  };

unsigned frame_hash_func(const struct hash_elem*, void*);
bool frame_less_func(const struct hash_elem*, const struct hash_elem*, void*);
void frame_init(void);
void* get_frame(enum palloc_flags, void* upage);
void free_frame(void* kpage);
void free_frame_on_exit(void);
void frame_table_remove(void* kpage);

unsigned spte_hash_func(const struct hash_elem*, void*);
bool spte_less_func(const struct hash_elem*, const struct hash_elem*, void*);
void spte_destroy_func(struct hash_elem*, void*);
bool spt_add_page(struct thread* t, void* upage, 
                  enum page_status status, void* kpage);
struct supplemental_page_table_entry* 
       spt_lookup(struct thread* t, void* upage);
bool activate_page(struct thread* t, void* upage);

void swap_init(void);
void swap_in(uint32_t, void*);
uint32_t swap_out(void*);
void swap_free (uint32_t);
void page_daemon(void);

struct mmap_list_entry* id_to_mle(mmapid id);
void munmap_id(mmapid id);
void munmap_on_exit(void);

#else
/* if VM not invoked */
#define get_frame(X, Y) palloc_get_page(X)
#define free_frame(X) palloc_free_page(X)

#endif
#endif
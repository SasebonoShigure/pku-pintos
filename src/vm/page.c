#include "vm/page.h"
#include <hash.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>
#include "userprog/pagedir.h"
#include <bitmap.h>
#include "devices/block.h"
#include <list.h>

#define BLOCK_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
/* lock_acquire顺序：frame_lock filesys_lock swap_lock  */
/* frame相关数据结构的锁 */
struct lock frame_lock;
static struct hash frame_hash_table;
/* swap的bitmap和block的锁 */
static struct lock swap_lock;       /* 保护swap block */
static struct block *swap_block;
// 0空1非空
static struct bitmap *swap_bitmap;  /* 指示swap slot占用状态 */
static size_t swap_maxnum;          /* swap最大页数量 */

static struct list clock_list;      /* clock algorithm用的 */
static struct list_elem* clock_ptr; /* clock algorithm指针 */

/* 必须在持有frame_lock的上下文中调用
swap_out一个页，并处理spt、fht、pagedir */
void page_daemon()
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  ASSERT(!list_empty(&clock_list))
  size_t n = hash_size(&frame_hash_table);
  struct frame_hash_table_entry * fhte;

  for(uint32_t i = 0; i < 2 * n; i++)
  {
    /* 为什么在这要判断list_end: frame_table_remove中
       可能调用过list_next(clock_ptr) */
    if (clock_ptr == NULL || clock_ptr == list_end(&clock_list))
    {
      clock_ptr = list_begin(&clock_list);
    }
    else
    {
      clock_ptr = list_next(clock_ptr);
    }
    if (clock_ptr == list_end(&clock_list))
    {
      clock_ptr = list_begin(&clock_list);
    }
    fhte = list_entry(clock_ptr, struct frame_hash_table_entry, celem);
    ASSERT(fhte->t);
    ASSERT(is_thread(fhte->t));
    if( pagedir_is_accessed(fhte->t->pagedir, fhte->upage))
    {
      pagedir_set_accessed(fhte->t->pagedir, fhte->upage, false);
      continue;
    }
    break;
  }

  /*先处理pagedir，这样将要被evict的页所属的线程
    再访问这个页的时候会fault，进入activate_page之前
    会被frame_lock拦住，实现了只要一个页被选中要驱逐，
    对其的访问都会被阻塞
    */
  ASSERT(fhte);
  ASSERT(is_thread(fhte->t));
  
  pagedir_clear_page(fhte->t->pagedir, fhte->upage);
  bool dirty = pagedir_is_dirty(fhte->t->pagedir, fhte->upage);
  if (dirty)
  {
    uint32_t index = swap_out(fhte->kpage);
    // 处理spt
    struct supplemental_page_table_entry* spte = 
           spt_lookup(fhte->t, fhte->upage);
    ASSERT(spte);
    spte->status = SWAPPED_OUT;
    spte->kpage = NULL;
    spte->swap_index = index;
  }
  else
  {
    struct supplemental_page_table_entry* spte = 
           spt_lookup(fhte->t, fhte->upage);
    ASSERT(spte);
    spte->kpage = NULL;
    /* 其实这一页可能是之前是DEMAND_ZERO来的，但是DEMAND_ZERO的页
       read_bytes是0，在后续activate_page时对于read_bytes==0的页
       处理方式和DEMAND_ZERO一样 */
    spte->status = LAZY_LOAD; 
  }
  free_frame(fhte->kpage);
}

/* unmap given mmapid, 写回文件,会从mmap_list remove mle */
void munmap_id(mmapid id)
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  struct thread* t = thread_current();
  struct mmap_list_entry* mle = id_to_mle(id);
  ASSERT(mle != NULL);
  ASSERT(mle->file != NULL)

  uint32_t offset;
  uint32_t file_size = mle->size;
  for(offset = 0; offset < file_size; offset += PGSIZE)
  {
    void *upage = (int8_t*)mle->upage + offset;
    struct supplemental_page_table_entry *spte = spt_lookup(t, upage);
    ASSERT(spte != NULL)
    ASSERT(mle->file != NULL)
    uint32_t bytes_write;

    switch (spte->status)
    {
    case IN_USE:
      // 确认在内存里
      ASSERT (spte->kpage != NULL);
      // 不dirty不用写回
      if (pagedir_is_dirty(t->pagedir, upage))
      {
        lock_acquire(&filesys_lock);
        file_seek(mle->file, offset);
        bytes_write = 0;
        while (bytes_write < spte->read_bytes)
        {
          bytes_write += file_write(mle->file, (int8_t*)upage + bytes_write, 
                                    spte->read_bytes - bytes_write);
        }
        lock_release(&filesys_lock);
      }
      pagedir_clear_page(t->pagedir, upage);
      free_frame (spte->kpage);
      break;
    case SWAPPED_OUT:
      // swap出去的一定dirty
      activate_page(t, spte->upage);
      ASSERT(spte->status == IN_USE);
      ASSERT (spte->kpage != NULL);
      lock_acquire(&filesys_lock);
      file_seek(mle->file, offset);
      bytes_write = 0;
      while (bytes_write < spte->read_bytes)
      {
        bytes_write += file_write(mle->file, (int8_t*)upage + bytes_write, 
                                  spte->read_bytes - bytes_write);
      }
      lock_release(&filesys_lock);
      pagedir_clear_page(t->pagedir, upage);
      free_frame (spte->kpage);
      break;
    case LAZY_LOAD:
      // 什么也不用管
      break;
    default:
      PANIC ("unknown status of spte");
    }

    // 处理spt
    hash_delete(t->supplemental_page_table, &spte->elem);
  }
    lock_acquire(&filesys_lock);
    file_close(mle->file);
    lock_release(&filesys_lock);
    // 处理mle
    list_remove(&mle->elem);
    free(mle);
}

/* 在进程退出时调用， */
void munmap_on_exit()
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  struct thread* t = thread_current();
  mmapid id;
  while(!list_empty(&t->mmap_list))
  {
    id = list_entry(list_front(&t->mmap_list), 
                    struct mmap_list_entry, elem)->id;
    munmap_id(id);
  }
}


/* 获取swap_block，创建bitmap */
void swap_init()
{
  lock_init(&swap_lock);
  swap_block = block_get_role(BLOCK_SWAP);
  ASSERT(swap_block != NULL);

  swap_maxnum = block_size(swap_block) / BLOCK_PER_PAGE;
  swap_bitmap = bitmap_create(swap_maxnum);
  ASSERT(swap_bitmap != NULL);
  bitmap_set_all(swap_bitmap, false);
}

/* 只负责把kpage放到swap block里 */
uint32_t swap_out(void* kpage)
{
  
  lock_acquire(&swap_lock);
  uint32_t index = bitmap_scan(swap_bitmap, 0, 1, false);
  ASSERT (index != BITMAP_ERROR);
  for (uint32_t i = 0; i < BLOCK_PER_PAGE; i++)
  {
    block_write(swap_block, index * BLOCK_PER_PAGE + i, 
                (int8_t*)kpage + i * BLOCK_SECTOR_SIZE);
  }
  bitmap_set(swap_bitmap, index, true);
  lock_release(&swap_lock);
  return index;
}

/* 只负责从swap_block拿到kpage，调用同时需要手动设置dirty */
void swap_in(uint32_t index, void* kpage)
{
  ASSERT (index < swap_maxnum);
  lock_acquire(&swap_lock);
  if (!bitmap_test(swap_bitmap, index))
  {
    PANIC ("swapping in from a empty block\n");
  }
  for (uint32_t i = 0; i < BLOCK_PER_PAGE; ++ i) {
    block_read(swap_block, index * BLOCK_PER_PAGE + i, 
               (int8_t*)kpage + i * BLOCK_SECTOR_SIZE);
  }
  bitmap_set(swap_bitmap, index, false);
  lock_release(&swap_lock);
}

void swap_free(uint32_t index)
{
  ASSERT (index < swap_maxnum);
  lock_acquire(&swap_lock);
  if (!bitmap_test(swap_bitmap, index))
  {
    PANIC ("freeing a empty block\n");
  }
  bitmap_set(swap_bitmap, index, false);
  lock_release(&swap_lock);
}

void frame_init()
{
  lock_init (&frame_lock);
  hash_init (&frame_hash_table, frame_hash_func, frame_less_func, NULL);
  list_init (&clock_list);
  clock_ptr = NULL;
}

/* palloc_get_page，维护frame_table，**不负责pagedir的维护** 返回kpage */
void* get_frame(enum palloc_flags flag, void* upage)
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  ASSERT((uint32_t)upage % PGSIZE == 0);

  void *kpage = palloc_get_page (PAL_USER | flag);
  // allocate failed
  if (kpage == NULL)
  {
    return NULL;
  }
  // 在free_frame()中free
  struct frame_hash_table_entry* fhte = 
         (struct frame_hash_table_entry*)
         malloc(sizeof(struct frame_hash_table_entry));
  if(fhte == NULL)
  {
    palloc_free_page(kpage);
    PANIC("malloc failed in get_frame()\n");
    return NULL;
  }

  fhte->t = thread_current();
  fhte->kpage = kpage;
  fhte->upage = upage;
  
  hash_insert (&frame_hash_table, &fhte->elem);
  list_push_back (&clock_list, &fhte->celem);

  return kpage;
}

/* palloc_free_page，同时会调用frame_table_remove */
void free_frame(void* kpage)
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  ASSERT((uint32_t)kpage % PGSIZE == 0);
  palloc_free_page(kpage);
  frame_table_remove(kpage);
}

/* 仅从fht删掉并free kpage对应的fhte */
void frame_table_remove(void* kpage)
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  ASSERT((uint32_t)kpage % PGSIZE == 0);
  // 临时的fhte，用于在哈希表中查询
  struct frame_hash_table_entry temp;
  temp.kpage = kpage;
  struct hash_elem *h = hash_find(&frame_hash_table, &temp.elem);
  ASSERT (h);

  struct frame_hash_table_entry* fhte = 
         hash_entry(h,struct frame_hash_table_entry, elem);
  // 重要：如果clock_ptr指向要的fhte被remove，下次list_next会有undefined behavior
  if (clock_ptr == &fhte->celem)
  {
    clock_ptr = list_next(&fhte->celem);
  }
  list_remove (&fhte->celem);
  hash_delete (&frame_hash_table, &fhte->elem);
  
  // hash_table中删掉的项，free掉
  free(fhte);
}

/* 在process将要退出时调用，根据spt清除fhte、并根据spt状态对具体物理页进行操作 */
void free_frame_on_exit()
{
  ASSERT(lock_held_by_current_thread(&frame_lock));
  struct thread* t = thread_current();
  struct hash* spt = t->supplemental_page_table;
  struct supplemental_page_table_entry* spte;
  struct hash_iterator it;
  hash_first(&it, spt);
  while (hash_next(&it))
  {
    spte = hash_entry(hash_cur(&it), 
                      struct supplemental_page_table_entry, elem);
    switch (spte->status)
    {
      case IN_USE:
        ASSERT(spte->kpage != NULL);
        // process_exit会根据pagdir来palloc_free_page
        frame_table_remove(spte->kpage);
        break;
      case SWAPPED_OUT:
        // swap_out的时候已经删了fhte
        ASSERT(spte->kpage == NULL);
        swap_free(spte->swap_index);
        break;
      case DEMAND_ZERO:
        ASSERT(spte->kpage == NULL);
        break;
      case LAZY_LOAD:
        ASSERT(spte->kpage == NULL);
        break;
      default:
        PANIC("unknown status of spte\n");
    }
  }
}

/* 向spt添加条目，插入已有条目会panic，返回值没用 */
bool spt_add_page(struct thread* t, void* upage, 
                  enum page_status status, void* kpage)
{
  ASSERT(is_thread(t));
  ASSERT((uint32_t)upage % PGSIZE == 0);
  struct supplemental_page_table_entry *spte;
  //spt通过hash_destroy()来free spte
  spte = (struct supplemental_page_table_entry*)
         malloc(sizeof(struct supplemental_page_table_entry));
  if (status != IN_USE)
  {
    ASSERT(kpage == NULL);
    spte->kpage = NULL;
  }
  else
  {
    spte->kpage = kpage;
  }
  spte->upage = upage;
  spte->status = status;
  spte->swap_index = INT32_MAX;
  spte->writable = true;
  spte->file = NULL;
  spte->offset = INT32_MAX;
  spte->read_bytes = 0;
  spte->zero_bytes = PGSIZE;
  // hash_insert没有重复条目时return NULL
  if (hash_insert(t->supplemental_page_table, &spte->elem) == NULL)
  {
    // spt没有相同条目，成功插入
    return true;
  }
  else
  {
    // spt已经有相同条目
    free(spte);
    PANIC ("already has same entry in spt\n");
    return false;
  }
}

/* 在spt中寻找页，如果失败返回NULL */
struct supplemental_page_table_entry* 
spt_lookup(struct thread* t, void* upage)
{
  ASSERT(is_thread(t));
  struct supplemental_page_table_entry temp;
  temp.upage = upage;
  struct hash* spt = t->supplemental_page_table;
  struct hash_elem *elem = hash_find(spt, &temp.elem);
  if(elem == NULL)
  {
      return NULL;
  }
  return hash_entry(elem, struct supplemental_page_table_entry, elem);
}

/* 依据spt, 激活一个not exist的页, 向页表添加条目, 
   spt没有该条目时panic，palloc失败返回false*/
bool activate_page(struct thread* t, void* upage)
{
  ASSERT(is_thread(t));
  ASSERT (upage != NULL);
  ASSERT(lock_held_by_current_thread(&frame_lock));
  uint32_t* pagedir = t->pagedir;
  struct supplemental_page_table_entry* spte;
  spte = spt_lookup(t, upage);
  
  if(spte == NULL)
  {
    PANIC("activating a page that is not in spt");
    return false;
  }
  bool writable = spte->writable;
  void* kpage;
  
  if(!(kpage = get_frame(PAL_USER, upage)))
  {
    // 需要腾出空间
    page_daemon();
    kpage = get_frame(PAL_USER, upage);
  }
  if (!kpage)
  {
    PANIC("can't get frame in ativate_page\n");
  }
  ASSERT(spte->kpage == NULL);
  switch (spte->status)
  {
    case IN_USE:
      PANIC("activating an active page\n");
      break;
    case DEMAND_ZERO:
      memset(kpage, 0, PGSIZE);
      if (pagedir_get_page (t->pagedir, upage))
      {
        PANIC("upage %p in pagedir has been occupied\n", upage);
      }
      // pagedir_set_page会清除dirty bit，所以只能每个case分别pagedir_set_page
      if(!pagedir_set_page(pagedir, upage, kpage, writable))
      {
        PANIC("pagedir_set_page failed");
      }
      break;
    case SWAPPED_OUT:
      swap_in(spte->swap_index, kpage);
      if (pagedir_get_page (t->pagedir, upage))
      {
        PANIC("upage %p in pagedir has been occupied\n", upage);
      }
      // pagedir_set_page会清除dirty bit，所以只能每个case分别pagedir_set_page
      if(!pagedir_set_page(pagedir, upage, kpage, writable))
      {
        PANIC("pagedir_set_page failed");
      }
      pagedir_set_dirty(t->pagedir, upage, true);
      break;
    case LAZY_LOAD:
      // 如果read_bytes是零，可能是DEMAND_ZERO之后被驱逐的干净页
      if (spte->read_bytes > 0)
      {
        file_seek (spte->file, spte->offset);
        uint32_t read_bytes = 0;
        while (read_bytes < spte->read_bytes)
        {
          read_bytes += file_read(spte->file, 
                                  (uint8_t*)kpage + read_bytes, 
                                  spte->read_bytes - read_bytes);
        }
        memset ((int8_t*)kpage + read_bytes, 0, spte->zero_bytes);
      }
      else
      {
        memset (kpage, 0, spte->zero_bytes);
      }
      if (pagedir_get_page (t->pagedir, upage))
      {
        PANIC("upage %p in pagedir has been occupied\n", upage);
      }
      if(!pagedir_set_page(pagedir, upage, kpage, writable))
      {
        PANIC("pagedir_set_page failed");
      }
      break;
    default:
      PANIC("spte not being properly initialized\n");
  }
  
  spte->status = IN_USE;
  spte->swap_index = INT32_MAX;
  spte->kpage = kpage;

  return true;
}

/* 寻找当前thread的mmapid对应的mle，没找到返回NULL */
struct mmap_list_entry* id_to_mle(mmapid id)
{
  struct thread* t = thread_current();
  struct list_elem *e;
  e = list_begin(&t->mmap_list);
  while (e != list_end(&t->child_list))
  {
    struct mmap_list_entry *mle = 
           list_entry(e, struct mmap_list_entry, elem);
    if(mle->id == id)
    {
      return mle;
    }
    e = list_next(e);
  }
  return NULL;
}
unsigned spte_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct supplemental_page_table_entry* spte = 
         hash_entry(elem, struct supplemental_page_table_entry, elem);
  return hash_bytes(&spte->upage, sizeof(void*));
}

bool spte_less_func(const struct hash_elem* left, 
                    const struct hash_elem* right, void* aux UNUSED)
{
  struct supplemental_page_table_entry *left_spte = 
         hash_entry(left, struct supplemental_page_table_entry, elem);
  struct supplemental_page_table_entry *right_spte = 
         hash_entry(right, struct supplemental_page_table_entry, elem);
  return (uint32_t)(left_spte->upage) < (uint32_t)(right_spte->upage);
}

void spte_destroy_func(struct hash_elem* elem, void* aux UNUSED)
{
  struct supplemental_page_table_entry *spte = 
        hash_entry(elem, struct supplemental_page_table_entry, elem);
  free (spte);
}

unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_hash_table_entry *fhte = 
         hash_entry(elem, struct frame_hash_table_entry, elem);
  return hash_bytes(&fhte->kpage, sizeof(void*));
}

bool frame_less_func(const struct hash_elem *left, 
                     const struct hash_elem *right, void *aux UNUSED)
{
  struct frame_hash_table_entry *left_fhte = 
         hash_entry(left, struct frame_hash_table_entry, elem);
  struct frame_hash_table_entry *right_fhte = 
         hash_entry(right, struct frame_hash_table_entry, elem);
  return (uint32_t)(left_fhte->kpage) < (uint32_t)(right_fhte->kpage);
}
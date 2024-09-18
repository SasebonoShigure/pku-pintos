#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_funeral(void);
int get_new_fd(void);
struct file_list_entry* fd_to_fle(int fd);
bool fd_less(const struct list_elem *left, 
             const struct list_elem *right, 
             void* aux);
#endif /**< userprog/process.h */

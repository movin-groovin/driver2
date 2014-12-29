
#include <linux/module.h>
#include <linux/kernel.h> // including for sprintf
#include <linux/init.h>

#include <linux/unistd.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/atomic.h>
#include <asm/current.h> // current
#include <linux/fdtable.h> // struct files_struct
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/mutex.h> // for mutex of course
#include <linux/fs.h> // struct file at line 976
#include <linux/path.h> // struct path
#include <linux/dcache.h> // struct dentry
#include <linux/fs_struct.h> // for fs_struct from task_struct
#include <linux/sched.h> // struct task_struct

#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/completion.h>
#include <linux/kernel.h> // simple_strtoul
#include <linux/cred.h> // for commit_creds
#include <asm/param.h> // HZ value

#include <linux/kthread.h> // for kthread_run



#define NUMBER_OF_FUNCTIONS 4

#define SYS_READ_NUM 0
#define SYS_WRITE_NUM 1
#define SYS_OPEN_NUM 2
#define SYS_OPENAT_NUM 3


typedef long (*READ_P)(unsigned int fd, char *buf, size_t count);
typedef long (*WRITE_P)(unsigned int fd, const char *buf, size_t count);
typedef int (*OPEN_P)(const char *, int, umode_t);
typedef int (*OPENAT_P)(int, const char *, int, umode_t);

typedef struct _DATA_FN {
	void *scltPtr;
	int sysNum;
	void *newPtr;
	void **oldPtr;
} DATA_FN, *PDATA_FN;


typedef struct _SYSSERV_INFO {
	void *sysPtrNew;
	void *sysPtrOld;
	unsigned sysNum;
	atomic64_t numOfCalls;
} SYSSERV_INF, *PSYSSERV_INF;











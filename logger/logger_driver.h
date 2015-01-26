
#include <linux/module.h>
#include <linux/kernel.h> // including for sprintf
#include <linux/init.h>
#include <linux/version.h> // for LINUX_VERSION_CODE and KERNEL_VERSION (1,2,3)

#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <asm/param.h> // HZ value
#include <linux/list.h>

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/mutex.h> // for mutex of course
#include <linux/sem.h> // semaphores
#include <linux/rwsem.h>

#include <linux/fs.h> // struct file at line 976
#include <linux/path.h> // struct path
#include <linux/dcache.h> // struct dentry
#include <linux/fs_struct.h> // for fs_struct from task_struct
#include <linux/file.h> // fget/fput/struct file
#include <linux/dirent.h>

#include <linux/kthread.h> // for kthread_run
#include <linux/mm_types.h> // mm_struct
#include <linux/sched.h> // struct task_struct
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/threads.h> // for PID_MAX_LIMIT

#include <linux/cdev.h>
#include <linux/device.h>

#include "ioctls.h"


#define MY_OWN_DEBUG


#define NUMBER_OF_FUNCTIONS 4
#define SYS_READ_NUM 0
#define SYS_WRITE_NUM 1
#define SYS_OPEN_NUM 2
#define SYS_OPENAT_NUM 3

#define MAX_MEM_SIZE (2 * 1024 * 1024)

#define FIRST_MINOR 0
#define MINOR_CNT 1

#define MAX_NUM_RULES 64



typedef long (*READ_P)(unsigned int fd, char *buf, size_t count);
typedef long (*WRITE_P)(unsigned int fd, const char *buf, size_t count);
typedef int (*OPEN_P)(const char *, int, umode_t);
typedef int (*OPENAT_P)(int, const char *, int, umode_t);

int ioctlOpen (struct inode *i, struct file *f);
int ioctlClose (struct inode *i, struct file *f);
long ioctlIoctl (struct file *f, unsigned int cmd, unsigned long arg);



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



typedef struct _IOCTL_INTERFACE {
	dev_t majMinNum;
	struct cdev charDevice;
	struct class *devClassPtr;
} IOCTL_INTERFACE, *PIOCTL_INTERFACE;



struct RULES_ENTRY_PID {
	pid_t pid;
	struct list_head list;
};

struct RULES_ENTRY_NAME {
	char name[2 * PATH_MAX + 2 * 2];
	struct list_head list;
};

struct RULES_HEAD {
	int onOf; // 1 - on; 0 - off
	int num;
	struct list_head head;
};

typedef struct _LOGCHECK_RULES {
	struct rw_semaphore syncRules;
	struct RULES_HEAD excHeadPids;
	struct RULES_HEAD incHeadPids;
	struct RULES_HEAD execHeadNames;
	struct RULES_HEAD fileHeadNames;
	int stopLogging;
} LOGCHECK_RULES, *PLOGCHECK_RULES;





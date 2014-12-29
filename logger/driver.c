
#include "driver.h"

//
// globals
//
SYSSERV_INF *g_sysServArr;
void *g_sysCallTable;
struct cpumask *g_cpusMask;
char *g_logBuffer;
size_t g_logBufSize;
const size_t g_maxLogBufSize = 10 * (1024 * 1024);
const size_t g_limitWriteFileSize = 8 * (1024 * 1024);
struct mutex g_logBuffLock;
struct file *g_logFile;
struct task_struct *g_loggerTask;
atomic_t g_stopLogTask;
const char *g_logFileName = "/tmp/logger_driver.log";//"/var/log/logger_driver.log";
const int g_secWriteAtTime = 1 * HZ;
const int g_secWait = 5 * HZ;

// ==============================================
// ============ Service functions ===============
// ==============================================

//
// ks is kernal space
//
char* GetProcessPidEuidEgid(char *ksMem, size_t size) {
	const size_t minSize = 128; //64 * 3 * sizeof(size_t);
	int ret;
	
	if (size < minSize)
		return NULL;
	ret = sprintf(ksMem, "pid: %d; ", current->tgid);
	ret = sprintf(ksMem + ret, "euid: %d, egid: %d\n", current_euid(), current_egid());
	sprintf(ksMem + ret, "\n");
	
	return ksMem;
}

char* GetFilenameByFd(int fd, char *ksMem, size_t size) {
	struct file *procFile;
	const size_t needMemSize = PATH_MAX * 2 + 256;
	char *fileName, *retPtr;
	
	
	if (size < needMemSize)
		return NULL;
	
	if (IS_ERR(procFile = fget(fd))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of fget, ret value: %p\n", procFile);
#endif
		return NULL;
	}
	if (NULL == (fileName = kmalloc (PATH_MAX * 2, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p\n", fileName);
#endif
		fput(procFile);
		return NULL;
	}
	
	retPtr = d_path(&procFile->f_path, fileName, PATH_MAX * 2 - 1 * 2);
	sprintf(ksMem, "%s; ", retPtr ? retPtr : "can't get file name");
	
	kfree(fileName);
	fput(procFile);
	
	
	return ksMem;
}

size_t WriteDataToFile (struct file *fileWriting, const void *buf, size_t count) {
	size_t ret = 0;
	mm_segment_t oldFs;
	loff_t posFile = fileWriting->f_pos;
	
	oldFs = get_fs();
	set_fs (KERNEL_DS);
	if ((ret = vfs_write (fileWriting, buf, count, &posFile)) < 0) {
#ifdef MY_OWN_DEBUG
		printk ("Error of writing at log file, ret: %d\n", (int)ret);
#endif
		ret = 0;
	}
	set_fs (oldFs);
	
	return ret;
}

void AddStringToLogBuf(const char *kernSpaceStr) {
	size_t ret;
	size_t strLen = strlen(kernSpaceStr);
	
	
	BUG_ON(g_logFile == NULL);
	
	mutex_lock(&g_logBuffLock);
	if (g_logBufSize + strLen >= g_limitWriteFileSize) {
		if ((ret = WriteDataToFile(g_logFile, g_logBuffer, g_logBufSize)) < 0) {
			printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
		}
		if ((ret = WriteDataToFile(g_logFile, kernSpaceStr, strLen)) < 0) {
			printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
		}
		g_logBufSize = 0;
	} else {
		memcpy(g_logBuffer + g_logBufSize, kernSpaceStr, strLen);
		g_logBufSize += strLen;
	}
	mutex_unlock(&g_logBuffLock);
	
	return;
}

void PutToBufferReadWriteParams(const char *prefString, unsigned int fd) {
	char *logStr;
	size_t strSize = 3 * PATH_MAX;
	int ret;
	
	
	BUG_ON(prefString == NULL);
	
	if ((logStr = kmalloc(strSize, GFP_KERNEL)) == NULL) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret value: %p; File: %s; Line: %d\n", logStr, __FILE__, __LINE__);
#endif
		return;
	}
	ret = sprintf(logStr, "%s: ", prefString);
	GetFilenameByFd(fd, logStr + ret, strSize - ret);
	GetProcessPidEuidEgid(logStr + strlen(logStr), strSize - strlen(logStr));
	AddStringToLogBuf(logStr);
	
	kfree(logStr);
	
	
	return;
}

char* GetNameFlagsModeByString(
	const char *fileNameInUS,
	int flags,
	umode_t mode,
	char *ksMem,
	size_t size
)
{
	size_t minSize = 2 * PATH_MAX + 256;
	char *bufMemory;
	size_t bufSize;
	
	
	if (size < minSize)
		return NULL;
	
	bufSize = strlen_user(fileNameInUS);
	if (NULL == (bufMemory = kmalloc(bufSize + 16, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret value: %p; File: %s; Line: %d\n", bufMemory, __FILE__, __LINE__);
#endif
		return NULL;
	}
	copy_from_user(bufMemory, fileNameInUS, bufSize);
	bufMemory[bufSize] = '\0';
	sprintf(ksMem, "file: %s, flags: %08X, mode: %08X; ", bufMemory, flags, mode);
	
	kfree(bufMemory);
	
	
	return ksMem;
}

char* GetCWDOfCurrentProcess(
	char *ksMem,
	size_t size
)
{
	struct path *pwd;
	char *bufMemory;
	size_t minSize = PATH_MAX * 2 + 256;
	
	
	if (size < minSize)
		return NULL;
	
	if ((bufMemory = kmalloc(minSize, GFP_KERNEL)) == NULL) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %s\n", bufMemory, __FILE__, __LINE__);
#endif
		return NULL;
	}
	spin_lock(&current->fs->lock);
	path_get(&current->fs->pwd);
	pwd = &current->fs->pwd;
	spin_unlock(&current->fs->lock);
	bufMemory = d_path((const struct path*)(pwd->dentry), bufMemory, minSize);
	sprintf(ksMem, "Current work directory: %s; ", bufMemory);
	
	path_put(pwd);
	kfree(bufMemory);
	
	
	return ksMem;
}

void PutToBufferOpenParams(
	const char *fileName,
	int flags,
	umode_t mode
)
{
	char *bufMemory;
	size_t needLength = 3 * PATH_MAX;
	const char *prefStr = "Opening a ";
	
	
	if (NULL == (bufMemory = kmalloc(needLength, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %s\n", bufMemory, __FILE__, __LINE__);
#endif
		return;
	}
	strcpy(bufMemory, prefStr);
	GetNameFlagsModeByString(
		fileName,
		flags,
		mode,
		bufMemory + strlen(prefStr),
		needLength - strlen(prefStr)
	);
	AddStringToLogBuf(bufMemory);
	
	kfree(bufMemory);
	
	
	return;
}

void PutToBufferOpenatParams(
	int dfd,
	const char *fileName,
	int flags,
	umode_t mode
)
{
	char *bufMemory;
	size_t needLength = 4 * PATH_MAX + 256;
	
	
	if (NULL == (bufMemory = kmalloc(needLength, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %s\n", bufMemory, __FILE__, __LINE__);
#endif
		return;
	}
	if (dfd == AT_FDCWD)
		GetCWDOfCurrentProcess(bufMemory, needLength);
	else
		GetFilenameByFd(dfd, bufMemory, needLength);
	
	GetNameFlagsModeByString(
		fileName,
		flags,
		mode,
		bufMemory + strlen(bufMemory),
		needLength - strlen(bufMemory)
	);
	AddStringToLogBuf(bufMemory);
	
	kfree(bufMemory);
	
	
	return;
}

// ===========================================
// ============= System services =============
// ===========================================

int NewOpen (const char *fileName, int flags, umode_t mode) {
	int ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_open\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_OPEN_NUM].numOfCalls);
	if (g_sysServArr[SYS_OPEN_NUM].sysPtrOld) {
		ret = ((OPEN_P)(g_sysServArr[SYS_OPEN_NUM].sysPtrOld)) (fileName, flags, mode);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at OPEN: %ld\n", atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls));
#endif
		PutToBufferOpenParams(fileName, flags, mode);
		
		atomic64_dec (& g_sysServArr[SYS_OPEN_NUM].numOfCalls);
		
		return ret;
	}
	else {
		atomic64_dec (& g_sysServArr[SYS_OPEN_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at OPEN: %ld\n", atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls));
#endif
		BUG_ON(1 == 1);
		return -EIO;
	}
	
	// return;
}
int NewOpenAt (int dfd, const char *fileName, int flags, umode_t mode) {
	int ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_openat\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls);
	if (g_sysServArr[SYS_OPENAT_NUM].sysPtrOld) {
		ret = ((OPENAT_P)(g_sysServArr[SYS_OPENAT_NUM].sysPtrOld)) (dfd, fileName, flags, mode);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at OPENAT: %ld\n", atomic64_read (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls));
#endif
		PutToBufferOpenatParams(dfd, fileName, flags, mode);
		
		atomic64_dec (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls);
		
		return ret;
	}
	else {
		atomic64_dec (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at OPENAT: %ld\n", atomic64_read (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls));
#endif
		BUG_ON(1 == 1);
		return -EIO;
	}
	
	// return;
}

ssize_t NewWrite (unsigned int fd, const char *buf, size_t count) {
	int ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_write\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_WRITE_NUM].numOfCalls);
	if (g_sysServArr[SYS_WRITE_NUM].sysPtrOld) {
		ret = ((WRITE_P)(g_sysServArr[SYS_WRITE_NUM].sysPtrOld)) (fd, buf, count);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at WRITE: %ld\n", atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls));
#endif
		PutToBufferReadWriteParams("Write call at file", fd);
		
		atomic64_dec (& g_sysServArr[SYS_WRITE_NUM].numOfCalls);
		
		return ret;
	}
	else {
		atomic64_dec (& g_sysServArr[SYS_WRITE_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at WRITE: %ld\n", atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls));
#endif
		BUG_ON(1 == 1);
		return -EIO;
	}
	
	// return;
}

ssize_t NewRead (unsigned int fd, char *buf, size_t count) {
	int ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_read\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_READ_NUM].numOfCalls);
	if (g_sysServArr[SYS_READ_NUM].sysPtrOld) {
		ret = ((READ_P)(g_sysServArr[SYS_READ_NUM].sysPtrOld)) (fd, buf, count);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at READ: %ld\n", atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls));
#endif
		PutToBufferReadWriteParams("Read call at file", fd);
		
		atomic64_dec (& g_sysServArr[SYS_READ_NUM].numOfCalls);
		
		return ret;
	}
	else {
		atomic64_dec (& g_sysServArr[SYS_READ_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter at READ: %ld\n", atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls));
#endif
		BUG_ON(1 == 1);
		return -EIO;
	}
	
	// return;
}

//
// Start/stop functions
//

void Fillg_sysServArr (void *SysServTable) {
	g_sysServArr[SYS_READ_NUM].sysPtrNew = &NewRead;
	g_sysServArr[SYS_READ_NUM].sysPtrOld = ((void**)SysServTable)[__NR_read];
	g_sysServArr[SYS_READ_NUM].sysNum = __NR_read;
	
	g_sysServArr[SYS_WRITE_NUM].sysPtrNew = &NewWrite;
	g_sysServArr[SYS_WRITE_NUM].sysPtrOld = ((void**)SysServTable)[__NR_write];
	g_sysServArr[SYS_WRITE_NUM].sysNum = __NR_write;
	
	g_sysServArr[SYS_OPEN_NUM].sysPtrNew = &NewOpen;
	g_sysServArr[SYS_OPEN_NUM].sysPtrOld = ((void**)SysServTable)[__NR_open];
	g_sysServArr[SYS_OPEN_NUM].sysNum = __NR_open;
	
	g_sysServArr[SYS_OPENAT_NUM].sysPtrNew = &NewOpenAt;
	g_sysServArr[SYS_OPENAT_NUM].sysPtrOld = ((void**)SysServTable)[__NR_openat];
	g_sysServArr[SYS_OPENAT_NUM].sysNum = __NR_openat;
	
	return;
}


void changeSyscallTable (void *scltPtr, int sysNum, void *newPtr, void **oldPtr) {
	// disable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("andq $0xfffffffffffeffff, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	*oldPtr = ((void**)scltPtr) [sysNum];
	((void**)g_sysCallTable) [sysNum] = newPtr;
	
	// enable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("xorq $0x0000000000010000, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	return;
}


int setFunc (void *datPtr) {
	DATA_FN *dat = (DATA_FN*)datPtr;
	
	changeSyscallTable (dat->scltPtr, dat->sysNum, dat->newPtr, dat->oldPtr);
	
	return 0;
}


int InitMemory(void) {
	// int var = 0;
	
	if (!(g_cpusMask = kmalloc (sizeof (struct cpumask), GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %016zX; File: %s; Line: %d\n", g_cpusMask, __FILE__, __LINE__);
#endif
		return -ENOMEM;
	}
	cpumask_clear (g_cpusMask);
	cpumask_bits (g_cpusMask)[0] = 1;
	
	if (!(g_sysServArr = kmalloc (NUMBER_OF_FUNCTIONS * sizeof (SYSSERV_INF), GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %016zX; File: %s; Line: %d\n", g_sysServArr, __FILE__, __LINE__);
#endif
		kfree (g_cpusMask);
		return -ENOMEM;
	}
	memset (g_sysServArr, 0, NUMBER_OF_FUNCTIONS * sizeof (SYSSERV_INF));
	
	if (!(g_logBuffer = kmalloc (g_maxLogBufSize, GFP_KERNEL))) {
		kfree(g_sysServArr);
		kfree(g_cpusMask);
		return -ENOMEM;
	}
	
	return 0;
}


void FreeMemory(void) {
	BUG_ON(g_logBuffer == NULL);
	BUG_ON(g_sysServArr == NULL);
	BUG_ON(g_cpusMask == NULL);
	
	kfree(g_logBuffer);
	kfree(g_sysServArr);
	kfree(g_cpusMask);
	
	return;
}


void* FindSystemServiceTablePtr(void) {
	void *stPtr = NULL;
	int i, lo, hi;
	void *system_call;
	unsigned char *ptr;
	
	//asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR));
	rdmsr (MSR_LSTAR, lo, hi);
	system_call = (void*)(((long)hi<<32) | lo);
	
	// 0xff14c5 - is opcode of relative call instruction at x64 (relative address is 4 byte value)
	// 500 may be dangerous, we go byte by byte at code of system_call
	for (ptr = system_call, i = 0; i < 500; i++) {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			stPtr = (void*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
			break;
		}
		ptr++;
	}
	
	return stPtr;
}


void RewriteSystemServiceTable(void) {
	DATA_FN dat;
	
	Fillg_sysServArr (g_sysCallTable);
	dat.scltPtr = g_sysCallTable;
	for (int i = 0; i < NUMBER_OF_FUNCTIONS; ++i) {
		dat.sysNum = g_sysServArr[i].sysNum;
		dat.newPtr = g_sysServArr[i].sysPtrNew;
		dat.oldPtr = & g_sysServArr[i].sysPtrOld;
		
		stop_machine(&setFunc, &dat, g_cpusMask);
	}
	
	return;
}


void ResoreSystemServiceTable(void) {
	DATA_FN dat = {g_sysCallTable};
	
	for (int i = 0; i < NUMBER_OF_FUNCTIONS; ++i) {
		dat.sysNum = g_sysServArr[i].sysNum;
		dat.newPtr = g_sysServArr[i].sysPtrOld;
		dat.oldPtr = & g_sysServArr[i].sysPtrOld;
		
		stop_machine(&setFunc, &dat, g_cpusMask);
	}
	
	return;
}


void WaitServicesTermination(void) {
	// int var = 0;
	
	while (atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls) ||
		   atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls) ||
		   atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls) ||
		   atomic64_read (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls)
		  )
	{
		set_current_state (TASK_INTERRUPTIBLE);
#ifdef MY_OWN_DEBUG
		printk ("Waiting, read cnt: %ld, readdir cnt: %ld\n",
		    atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls) ||
		    atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls) ||
		    atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls) ||
		    atomic64_read (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls)
		);
#endif
		schedule_timeout (g_secWait);
	}
	// For escaping of race unload driver condition (and of course this situation can happen)
	// To unload the driver is rather unsafable
	set_current_state (TASK_INTERRUPTIBLE);
	schedule_timeout (g_secWait);
	
	return;
}


int LoggerThread(void *data) {
	size_t ret;
	
	while (!atomic_read(&g_stopLogTask)) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(g_secWriteAtTime);
		
		mutex_lock(&g_logBuffLock);
		if ((ret = WriteDataToFile (g_logFile, g_logBuffer, g_logBufSize)) < 0) {
			printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
		}
		g_logBufSize = 0;
		mutex_unlock(&g_logBuffLock);
	}
	
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(g_secWriteAtTime);
	
	mutex_lock(&g_logBuffLock);
	if ((ret = WriteDataToFile (g_logFile, g_logBuffer, g_logBufSize)) < 0) {
		printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
	}
	g_logBufSize = 0;
	mutex_unlock(&g_logBuffLock);
	
	atomic_set(&g_stopLogTask, 0);
	
	return 0;
}


void WaitLoggerThreadTermination(void) {
	// int val = 0;
	
	atomic_set(&g_stopLogTask, 1);
	while (atomic_read(&g_stopLogTask)) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(g_secWait);
	}
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(g_secWait);
	
	return;
}

void* CreateThread(int (*ThreadPtr)(void*)) {
	struct task_struct *newThread;
	
	atomic_set(&g_stopLogTask, 0);
	
	newThread = kthread_run(ThreadPtr, NULL, "driver_logger");
	if (IS_ERR(newThread)) {
		printk("Error of filp_open, ret: %p; File: %s; Line: %d\n", newThread, __FILE__, __LINE__);
		return newThread;
	}
	g_loggerTask = newThread;
	
	return NULL;
}

void InitLocks(void) {
	mutex_init(&g_logBuffLock);
	
	return;
}

void* OpenFiles(void) {
	void *ptr;
	
	ptr = filp_open(g_logFileName, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH);
	if (IS_ERR(ptr)) {
		printk("Error of filp_open, ret: %p; File: %s; Line: %d\n", ptr, __FILE__, __LINE__);
		return ptr;
	}
	g_logFile = ptr;
	
	return ptr;
}

void CloseFiles(void) {
	filp_close(g_logFile, NULL);
	
	return;
}


int start (void) {
	void *retPtr;
	
	if (InitMemory())
		return -ENOMEM;
	
	if (!(g_sysCallTable = FindSystemServiceTablePtr ())) {
		FreeMemory();
		return -ENOSYS;
	} else {
#ifdef MY_OWN_DEBUG
		printk ("Have found g_sysCallTable address: %p\n", g_sysCallTable);
#endif
	}
	
	if ((retPtr = OpenFiles ())) {
		FreeMemory();
		return (int)retPtr;
	}
	InitLocks();
	retPtr = CreateThread(LoggerThread);
	if (IS_ERR(retPtr)) {
		CloseFiles();
		FreeMemory();
		return (int)retPtr; 
	}
	RewriteSystemServiceTable();
	
	return 0;
}

void stop (void) {	
#ifdef MY_OWN_DEBUG
	printk ("Unloading start\n");
#endif
	ResoreSystemServiceTable();
	WaitServicesTermination();
	WaitLoggerThreadTermination();
	CloseFiles();
	FreeMemory();
	
	return;
}



module_init(start);
module_exit(stop);
MODULE_LICENSE ("GPL");





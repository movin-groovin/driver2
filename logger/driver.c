
#include "driver.h"

//
// globals
//
SYSSERV_INF *g_sysServArr;
void *g_sysCallTable;
struct cpumask *g_cpusMask;
char *g_logBuffer;
size_t g_logBufSize;
const size_t g_maxLogBufSize = MAX_MEM_SIZE;
const size_t g_limitWriteFileSize = MAX_MEM_SIZE - (128 * 1024);
struct mutex g_logBuffLock;
struct file *g_logFile;
struct task_struct *g_loggerTask;
atomic_t g_stopLogTask;
const char *g_logFileName = "/tmp/logger_driver.log";//"/var/log/logger_driver.log";
const int g_secWriteAtTime = 1 * HZ;
const int g_secWait = 5 * HZ;
IOCTL_INTERFACE g_ioctlData;
struct file_operations g_fopsQuery = {
	.owner = THIS_MODULE,
	.open = &ioctlOpen,
	.release = &ioctlClose,
	.unlocked_ioctl = &ioctlIoctl
};
LOGCHECK_RULES g_logRules;

// ==============================================
// ============ Service functions ===============
// ==============================================

//
// ks is kernal space
//
char* GetCurrentProcessPidEuidEgid(char *ksMem, size_t size) {
	const size_t minSize = 128; //64 * 3 * sizeof(size_t);
	int ret;
	
	if (size < minSize) {
#ifdef MY_OWN_DEBUG
		printk ("Too little buffer, at GetCurrentProcessPidEuidEgid\n");
#endif
		return NULL;
	}
	ret = sprintf(ksMem, "pid: %d, ", current->tgid);
	ret = sprintf(ksMem + ret, "euid: %d, egid: %d", current_euid(), current_egid());
	
	return ksMem;
}

char *GetStatus(
	char *ksMem,
	size_t size,
	long ret
)
{
	size_t minSize = 64;
	
	ksMem[0] = '\0';
	if (size < minSize) {
#ifdef MY_OWN_DEBUG
		printk ("Too little buffer, at GetStatus\n");
#endif
		return NULL;
	}
	
	if (IS_ERR((void*)ret)) {
		sprintf(ksMem, "%s, ret: %p", "error", (void*)ret);
	} else {
		sprintf(ksMem, "%s, ret: %p", "success", (void*)ret);
	}
	
	return ksMem;
}

char* GetProcessExeFile(
	char *ksMem,
	size_t size,
	struct task_struct *task
)
{
	size_t minSize = 2 * PATH_MAX + 128;
	struct mm_struct *m_task;
	char *exeName, *retPtr;
	struct file *exeFile;
	
	
	ksMem[0] = '\0';
	if (size < minSize) {
#ifdef MY_OWN_DEBUG
		printk ("Too little buffer, at GetProcessExeFile\n");
#endif
		return NULL;
	}
	
	if (!(m_task = task->mm)) {
#ifdef MY_OWN_DEBUG
		printk ("Mm of current task_struct is NULL\n");
#endif
		return NULL;
	}
	
	if (!(exeName = kmalloc(minSize, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret value: %p; File: %s; Line: %d\n", exeName, __FILE__, __LINE__);
#endif
		return NULL;
	}
	
	down_read(&m_task->mmap_sem);
	if (!(exeFile = m_task->exe_file)) {
#ifdef MY_OWN_DEBUG
		printk ("Exe file in mm of current task_struct is NULL\n");
#endif
		up_read(&m_task->mmap_sem);
		kfree(exeName);
		return NULL;
	}
	retPtr = d_path(&exeFile->f_path, exeName, minSize);
	sprintf(ksMem, "exec file: %s", IS_ERR(retPtr) ? "can't get file name" : retPtr);
	up_read(&m_task->mmap_sem);
	
	kfree(exeName);
	
	
	return ksMem;
}

char* GetFilenameByFd(int fd, char *ksMem, size_t size) {
	struct file *procFile;
	const size_t needMemSize = PATH_MAX * 2 + 256;
	char *fileName, *retPtr;
	
	
	if (size < needMemSize)
		return NULL;
	
	if (!(procFile = fget(fd))) {
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
	sprintf(ksMem, "%s", IS_ERR(retPtr) ? "can't get file name" : retPtr);
	
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
	}
	fileWriting->f_pos = posFile;
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
#ifdef MY_OWN_DEBUG
			printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
#endif
		}
		if ((ret = WriteDataToFile(g_logFile, kernSpaceStr, strLen)) < 0) {
#ifdef MY_OWN_DEBUG
			printk ("Error of WriteDataToFile, ret: %016zX; File: %s, Line: %d\n", ret, __FILE__, __LINE__);
#endif
		}
		g_logBufSize = 0;
	} else {
		memcpy(g_logBuffer + g_logBufSize, kernSpaceStr, strLen);
		g_logBufSize += strLen;
	}
	mutex_unlock(&g_logBuffLock);
	
	
	return;
}

void PutToBufferReadWriteParams(
	const char *prefString,
	unsigned int fd,
	long ret
)
{
	char *logStr;
	size_t strSize = 5 * PATH_MAX;
	int retNum;
	
	
	BUG_ON(prefString == NULL);
	
	if ((logStr = kmalloc(strSize, GFP_KERNEL)) == NULL) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret value: %p; File: %s; Line: %d\n", logStr, __FILE__, __LINE__);
#endif
		return;
	}
	retNum = sprintf(logStr, "%s: ", prefString);
	GetFilenameByFd(fd, logStr + retNum, strSize - retNum);
	strcat(logStr, "; ");
	GetProcessExeFile(logStr + strlen(logStr), strSize - strlen(logStr), current);
	strcat(logStr, "; ");
	GetCurrentProcessPidEuidEgid(logStr + strlen(logStr), strSize - strlen(logStr));
	strcat(logStr, "; ");
	GetStatus(logStr + strlen(logStr), strSize - strlen(logStr), ret);
	strcat(logStr, "\n");
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
	
	if ((bufSize = strlen_user(fileNameInUS)) > 2 * PATH_MAX) {
#ifdef MY_OWN_DEBUG
		printk("Too long filename from usermode\n");
#endif
		return NULL;
	}
	if (NULL == (bufMemory = kmalloc(bufSize + 16, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret value: %p; File: %s; Line: %d\n", bufMemory, __FILE__, __LINE__);
#endif
		return NULL;
	}
	copy_from_user(bufMemory, fileNameInUS, bufSize);
	bufMemory[bufSize] = '\0';
	sprintf(ksMem, "file: %s, flags: %08X, mode: %08X", bufMemory, flags, mode);
	
	kfree(bufMemory);
	
	
	return ksMem;
}

char* GetCWDOfCurrentProcess(
	char *ksMem,
	size_t size
)
{
	struct path *pwd;
	char *bufMemory, *retDpath;
	size_t minSize = PATH_MAX * 2 + 256;
	
	
	if (size < minSize)
		return NULL;
	
	if ((bufMemory = kmalloc(minSize, GFP_KERNEL)) == NULL) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", bufMemory, __FILE__, __LINE__);
#endif
		return NULL;
	}
	spin_lock(&current->fs->lock);
	path_get(&current->fs->pwd);
	pwd = &current->fs->pwd;
	spin_unlock(&current->fs->lock);
	retDpath = d_path((const struct path*)(pwd->dentry), bufMemory, minSize);
	sprintf(ksMem, "current work directory: %s", IS_ERR(retDpath) ? "can't get file's name" : retDpath);
	
	path_put(pwd);
	kfree(bufMemory);
	
	
	return ksMem;
}

void PutToBufferOpenParams(
	const char *fileName,
	int flags,
	umode_t mode,
	long ret
)
{
	char *bufMemory;
	size_t needLength = 5 * PATH_MAX;
	const char *prefStr = "Opening a ";
	
	
	if (NULL == (bufMemory = kmalloc(needLength, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", bufMemory, __FILE__, __LINE__);
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
	strcat(bufMemory, "; ");
	GetProcessExeFile(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory), current);
	strcat(bufMemory, "; ");
	GetCurrentProcessPidEuidEgid(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory));
	strcat(bufMemory, "; ");
	GetStatus(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory), ret);
	strcat(bufMemory, "\n");
	AddStringToLogBuf(bufMemory);
	
	kfree(bufMemory);
	
	
	return;
}

void PutToBufferOpenatParams(
	int dfd,
	const char *fileName,
	int flags,
	umode_t mode,
	long ret
)
{
	char *bufMemory;
	size_t needLength = 7 * PATH_MAX;
	const char *prefStr = "Openat call from: ";
	
	
	if (NULL == (bufMemory = kmalloc(needLength, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", bufMemory, __FILE__, __LINE__);
#endif
		return;
	}
	
	strcpy(bufMemory, prefStr);
	if (dfd == AT_FDCWD)
		GetCWDOfCurrentProcess(bufMemory, needLength);
	else
		GetFilenameByFd(dfd, bufMemory, needLength);
	strcat(bufMemory, "; ");
	GetNameFlagsModeByString(
		fileName,
		flags,
		mode,
		bufMemory + strlen(bufMemory),
		needLength - strlen(bufMemory)
	);
	strcat(bufMemory, "; ");
	GetProcessExeFile(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory), current);
	strcat(bufMemory, "; ");
	GetCurrentProcessPidEuidEgid(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory));
	strcat(bufMemory, "; ");
	GetStatus(bufMemory + strlen(bufMemory), needLength - strlen(bufMemory), ret);
	strcat(bufMemory, "\n");
	AddStringToLogBuf(bufMemory);
	
	kfree(bufMemory);
	
	
	return;
}

int CheckLogRules (PLOGCHECK_RULES chkLogRulesPtr, pid_t pid) {
	struct RULES_ENTRY *present;
	
	
	down_read(&chkLogRulesPtr->syncRules);
	
	if (chkLogRulesPtr->stopLogging) // 3 rule
	{
		up_read(&chkLogRulesPtr->syncRules);
		return 0;
	} else if (chkLogRulesPtr->incHead.onOf) // 2 rule
	{
		list_for_each_entry(present, &chkLogRulesPtr->incHead.head, list) {
			if (present->pid == pid) {
				up_read(&chkLogRulesPtr->syncRules);
				return 1;
			}
		}
		up_read(&chkLogRulesPtr->syncRules);
		return 0;
	} else if (chkLogRulesPtr->excHead.onOf) // 1 rule
	{
		list_for_each_entry(present, &chkLogRulesPtr->excHead.head, list) {
			if (present->pid == pid) {
				up_read(&chkLogRulesPtr->syncRules);
				return 0;
			}
		}
		up_read(&chkLogRulesPtr->syncRules);
		return 1;
	}
	// default rule
	up_read(&chkLogRulesPtr->syncRules);
	
	
	return 1;
}

// ===========================================
// ============= System services =============
// ===========================================

int NewOpen (const char *fileName, int flags, umode_t mode) {
	long ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_open\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_OPEN_NUM].numOfCalls);
	if (g_sysServArr[SYS_OPEN_NUM].sysPtrOld) {
		ret = ((OPEN_P)(g_sysServArr[SYS_OPEN_NUM].sysPtrOld)) (fileName, flags, mode);
#ifdef MY_OWN_DEBUG
		//printk ("Number of counter at OPEN: %ld\n", atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls));
#endif
		if (CheckLogRules (&g_logRules, current->tgid))
			PutToBufferOpenParams(fileName, flags, mode, ret);
		
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
	long ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_openat\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls);
	if (g_sysServArr[SYS_OPENAT_NUM].sysPtrOld) {
		ret = ((OPENAT_P)(g_sysServArr[SYS_OPENAT_NUM].sysPtrOld)) (dfd, fileName, flags, mode);
#ifdef MY_OWN_DEBUG
		//printk ("Number of counter at OPENAT: %ld\n", atomic64_read (& g_sysServArr[SYS_OPENAT_NUM].numOfCalls));
#endif
		if (CheckLogRules (&g_logRules, current->tgid))
			PutToBufferOpenatParams(dfd, fileName, flags, mode, ret);
		
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

long NewWrite (unsigned int fd, const char *buf, size_t count) {
	long ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_write\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_WRITE_NUM].numOfCalls);
	if (g_sysServArr[SYS_WRITE_NUM].sysPtrOld) {
		ret = ((WRITE_P)(g_sysServArr[SYS_WRITE_NUM].sysPtrOld)) (fd, buf, count);
#ifdef MY_OWN_DEBUG
		//printk ("Number of counter at WRITE: %ld\n", atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls));
#endif
		if (CheckLogRules (&g_logRules, current->tgid))
			PutToBufferReadWriteParams("Write call at file", fd, ret);
		
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

long NewRead (unsigned int fd, char *buf, size_t count) {
	long ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_read\n");
#endif
	
	atomic64_inc (& g_sysServArr[SYS_READ_NUM].numOfCalls);
	if (g_sysServArr[SYS_READ_NUM].sysPtrOld) {
		ret = ((READ_P)(g_sysServArr[SYS_READ_NUM].sysPtrOld)) (fd, buf, count);
#ifdef MY_OWN_DEBUG
		//printk ("Number of counter at READ: %ld\n", atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls));
#endif
		if (CheckLogRules (&g_logRules, current->tgid))
			PutToBufferReadWriteParams("Read call at file", fd, ret);
		
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
	//atomic64_set(&g_sysServArr[SYS_READ_NUM].numOfCalls, 0);
	
	g_sysServArr[SYS_WRITE_NUM].sysPtrNew = &NewWrite;
	g_sysServArr[SYS_WRITE_NUM].sysPtrOld = ((void**)SysServTable)[__NR_write];
	g_sysServArr[SYS_WRITE_NUM].sysNum = __NR_write;
	//atomic64_set(&g_sysServArr[SYS_WRITE_NUM].numOfCalls, 0);
	
	g_sysServArr[SYS_OPEN_NUM].sysPtrNew = &NewOpen;
	g_sysServArr[SYS_OPEN_NUM].sysPtrOld = ((void**)SysServTable)[__NR_open];
	g_sysServArr[SYS_OPEN_NUM].sysNum = __NR_open;
	//atomic64_set(&g_sysServArr[SYS_OPEN_NUM].numOfCalls, 0);
	
	g_sysServArr[SYS_OPENAT_NUM].sysPtrNew = &NewOpenAt;
	g_sysServArr[SYS_OPENAT_NUM].sysPtrOld = ((void**)SysServTable)[__NR_openat];
	g_sysServArr[SYS_OPENAT_NUM].sysNum = __NR_openat;
	//atomic64_set(&g_sysServArr[SYS_OPENAT_NUM].numOfCalls, 0);
	
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
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", g_cpusMask, __FILE__, __LINE__);
#endif
		return -ENOMEM;
	}
	cpumask_clear (g_cpusMask);
	cpumask_bits (g_cpusMask)[0] = 1;
	
	if (!(g_sysServArr = kmalloc (NUMBER_OF_FUNCTIONS * sizeof (SYSSERV_INF), GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", g_sysServArr, __FILE__, __LINE__);
#endif
		kfree (g_cpusMask);
		return -ENOMEM;
	}
	memset (g_sysServArr, 0, NUMBER_OF_FUNCTIONS * sizeof (SYSSERV_INF));
	
	if (!(g_logBuffer = kmalloc (g_maxLogBufSize, GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", g_logBuffer, __FILE__, __LINE__);
#endif
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


void RestoreSystemServiceTable(void) {
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
		printk ("Waiting, cnt1: %zd, cnt2: %zd, cnt3: %zd, cnt4: %zd\n",
		    atomic64_read (& g_sysServArr[SYS_READ_NUM].numOfCalls),
		    atomic64_read (& g_sysServArr[SYS_WRITE_NUM].numOfCalls),
		    atomic64_read (& g_sysServArr[SYS_OPEN_NUM].numOfCalls),
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

void* OpenFile(const char *fileName) {
	void *ptr;
	
	ptr = filp_open(
		fileName,
		O_WRONLY | O_CREAT | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
	);
	if (IS_ERR(ptr)) {
		printk("Error of filp_open, ret: %p; File: %s; Line: %d\n", ptr, __FILE__, __LINE__);
		return ptr;
	}
	
	return ptr;
}

void CloseFile(struct file *file) {
	filp_close(file, NULL);
	
	return;
}

int RegisterDevice (PIOCTL_INTERFACE iocDataPtr) {
	int ret;
	struct device *devPtr;
	
	if ((ret = alloc_chrdev_region(&iocDataPtr->majMinNum, FIRST_MINOR, MINOR_CNT, "driver_one_driver")) < 0)
	{
#ifdef MY_OWN_DEBUG
		printk("Error of alloc_chrdev_region, ret: %d\n", ret);
#endif
		return 0;
	}
	cdev_init(&iocDataPtr->charDevice, &g_fopsQuery);
	if ((ret = cdev_add(&iocDataPtr->charDevice, iocDataPtr->majMinNum, MINOR_CNT)) < 0)
	{
#ifdef MY_OWN_DEBUG
		printk("Error of cdev_add, ret: %d\n", ret);
#endif
		return 0;
	}
	
	if (IS_ERR(iocDataPtr->devClassPtr = class_create(THIS_MODULE, "char_class")))
	{
#ifdef MY_OWN_DEBUG
		printk("Error of class_create, ret: %p\n", iocDataPtr->devClassPtr);
#endif
		cdev_del(&iocDataPtr->charDevice);
		unregister_chrdev_region(iocDataPtr->majMinNum, MINOR_CNT);
		return 0;
	}
	if (IS_ERR(devPtr = device_create(iocDataPtr->devClassPtr, NULL, iocDataPtr->majMinNum, NULL, "logger_driver")))
	{
#ifdef MY_OWN_DEBUG
		printk("Error of device_create, ret: %p\n", devPtr);
#endif
		class_destroy(iocDataPtr->devClassPtr);
		cdev_del(&iocDataPtr->charDevice);
		unregister_chrdev_region(iocDataPtr->majMinNum, MINOR_CNT);
		return 0;
	}
	
	return 1;
}

void UnregisterDevice (PIOCTL_INTERFACE iocDataPtr) {
	device_destroy(iocDataPtr->devClassPtr, iocDataPtr->majMinNum);
	class_destroy(iocDataPtr->devClassPtr);
	cdev_del(&iocDataPtr->charDevice);
	unregister_chrdev_region(iocDataPtr->majMinNum, MINOR_CNT);
	
	return;
}

int ioctlOpen (struct inode *i, struct file *f) {
	return 0;
}

int ioctlClose (struct inode *i, struct file *f) {
	return 0;
}

long ioctlIoctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct RULES_ENTRY *entryPtr;
	struct RULES_ENTRY *next, *present;
	long ret = 0;
	
	
	down_write(&g_logRules.syncRules);
	
	switch(cmd) {
		case EXCLUDE_PID:
			entryPtr = kmalloc(sizeof (struct RULES_ENTRY), GFP_KERNEL);
			if (!entryPtr) {
#ifdef MY_OWN_DEBUG
				printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", entryPtr, __FILE__, __LINE__);
#endif
				ret = -ENOMEM;
			} else {
				entryPtr->pid = arg;
				g_logRules.excHead.onOf = 1;
				g_logRules.excHead.num += 1;
				list_add(&entryPtr->list, &g_logRules.excHead.head);
			}
			break;
		
		case INCLUDE_PID:
			entryPtr = kmalloc(sizeof (struct RULES_ENTRY), GFP_KERNEL);
			if (!entryPtr) {
#ifdef MY_OWN_DEBUG
				printk ("Error of kmalloc, ret: %p; File: %s; Line: %d\n", entryPtr, __FILE__, __LINE__);
#endif
				ret = -ENOMEM;
			} else {
				entryPtr->pid = arg;
				g_logRules.incHead.onOf = 1;
				g_logRules.incHead.num += 1;
				list_add(&entryPtr->list, &g_logRules.incHead.head);
			}
			break;
		
		case STOP_LOGGING:
			g_logRules.stopLogging = 1;
			break;
		
		case CONTINUE_LOGGING:
			g_logRules.stopLogging = 0;
			break;
		
		case CLEAR_RULES:
			g_logRules.stopLogging = 0;
			
			list_for_each_entry_safe(present, next, &g_logRules.excHead.head, list) {
				list_del(&present->list);
				kfree(present);
			}
			g_logRules.excHead.num = 0;
			g_logRules.excHead.onOf = 0;
			
			list_for_each_entry_safe(present, next, &g_logRules.incHead.head, list) {
				list_del(&present->list);
				kfree(present);
			}
			g_logRules.incHead.num = 0;
			g_logRules.incHead.onOf = 0;
			
			break;
		
		case DELETE_FROM_EXCLUDE:
			list_for_each_entry(present, &g_logRules.excHead.head, list) {
				if (present->pid == arg) {
					list_del(&present->list);
					kfree(present);
					up_write(&g_logRules.syncRules);
					return ret;
				}
			}
			ret = -EINVAL;
			break;
		
		case DELETE_FROM_INCLUDE:
			list_for_each_entry(present, &g_logRules.incHead.head, list) {
				if (present->pid == arg) {
					list_del(&present->list);
					kfree(present);
					up_write(&g_logRules.syncRules);
					return ret;
				}
			}
			ret = -EINVAL;
			break;
		
		default:
			ret = -EINVAL;
	}
	
	up_write(&g_logRules.syncRules);
	
	
	return ret;
}

void InitLoggingRules(PLOGCHECK_RULES logChkRulesPtr) {
	init_rwsem(&logChkRulesPtr->syncRules);
	
	logChkRulesPtr->excHead.onOf = 0;
	logChkRulesPtr->excHead.num = 0;
	INIT_LIST_HEAD(&logChkRulesPtr->excHead.head);
	
	logChkRulesPtr->incHead.onOf = 0;
	logChkRulesPtr->incHead.num = 0;
	INIT_LIST_HEAD(&logChkRulesPtr->incHead.head);
	
	return;
}

void ReleaseLoggingRules(PLOGCHECK_RULES logChkRulesPtr) {
	struct RULES_ENTRY *next, *cur;
	
	down_write(&logChkRulesPtr->syncRules);
	list_for_each_entry_safe(cur, next, &logChkRulesPtr->excHead.head, list) {
		list_del(&cur->list);
		kfree(cur);
	}
	list_for_each_entry_safe(cur, next, &logChkRulesPtr->incHead.head, list) {
		list_del(&cur->list);
		kfree(cur);
	}
	up_write(&logChkRulesPtr->syncRules);
	
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
	
	if (IS_ERR(retPtr = OpenFile (g_logFileName))) {
		FreeMemory();
		return (int)retPtr;
	} else {
		g_logFile = retPtr;
	}
	InitLocks();
	retPtr = CreateThread(LoggerThread);
	if (IS_ERR(retPtr)) {
		CloseFile(g_logFile);
		FreeMemory();
		return (int)retPtr; 
	}
	InitLoggingRules(&g_logRules);
	if (!RegisterDevice (&g_ioctlData)) {
		WaitLoggerThreadTermination();
		CloseFile(g_logFile);
		FreeMemory();
		return -ENOMEM; 
	}
	RewriteSystemServiceTable();
	
	return 0;
}

void stop (void) {	
#ifdef MY_OWN_DEBUG
	printk ("Unloading start\n");
#endif
	RestoreSystemServiceTable();
	WaitServicesTermination();
	UnregisterDevice(&g_ioctlData);
	ReleaseLoggingRules(&g_logRules);
	WaitLoggerThreadTermination();
	CloseFile(g_logFile);
	FreeMemory();
	
	return;
}



module_init(start);
module_exit(stop);
MODULE_LICENSE ("GPL");





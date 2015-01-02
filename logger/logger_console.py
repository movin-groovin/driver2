#!/usr/bin/python
#-*-  coding:utf8 -*-


import sys,\
	   os,\
	   subprocess
import ioctls



# Global variables
pref_len = 3 # '.ko'
module_name_pref = str()
module_name = str()
commands = str()



def CheckRoot():
	if os.getuid() == 0:
		return True
	return False


def GetParameters(params):
	return (
		params[1],
		params[1][0 : len(params[1]) - pref_len],
		params[2],
		' '.join(params[3:])
	)


def LoadKernelModule(module_path):
	proc = subprocess.Popen(
		["/sbin/insmod", module_path],
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	if ret:
		msg = "Message from insmod: '{}'".format(proc.stderr.read()[:])
		print msg.replace('\n', '')
		return False
	return True


def UnloadKernelModule(module_name):
	proc = subprocess.Popen(
		["/sbin/rmmod ", module_name],
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	if ret:
		msg = "Message from rmmod: '{}'".format(proc.stderr.read()[:])
		print msg.replace('\n', '')
		return False
	return True


def CreateChilds(cmds):
	return True



def main():
	if len(sys.argv) < 4 or sys.argv[1] == '-h':
		print "Run so: ./script module_path device_path commands_for_log_processings\n"\
			  "Example 1: ./logger_console.py /home/user/driver.ko /dev/logger_driver "\
			  "tail -f /tmp/logger_driver.log\n"\
			  "Example 2: ./logger_console.py /home/user/driver.ko /dev/logger_driver "\
			  "tail -f /tmp/logger_driver.log | grep '.*Read.*'"
		return 1000
	
	module_name_pref, module_name, dev_name, commands = GetParameters(sys.argv)
	
	if not CheckRoot():
		print "Need run as root"
		return 1001
	
	
	if not LoadKernelModule(module_name_pref):
		print "Can't load module: {}".format(module_name_pref)
		return 1002
	
	try:
		fDev = open(dev_name)
	except IOError as Exc:
		print "Can't open {}".format(sys.argv[1])
		print Exc
		UnloadKernelModule(module_name)
		return 1003
	
	ioctls.SendCommand(fDev, ioctls.STOP_LOGGING)
	ioctls.SendCommand(fDev, ioctls.TRUNCATE_LOG_FILE)
	shell_pid, pids = CreateChilds(commands)
	ioctls.SendCommand(fDev, ioctls.EXCLUDE_PID, shell_pid)
	for pid in pids:
		ioctls.SendCommand(fDev, ioctls.EXCLUDE_PID, pid)
	ioctls.SendCommand(fDev, ioctls.CONTINUE_LOGGING)
	os.wait(shell_pid)
	
	UnloadKernelModule(module_name)
	
	
	return 0

	   
	   
if __name__ != '__main__':
	raise RuntimeError("Can't run like a module") 
else:
	try:
		main()
	except Exception as Exc:
		UnloadKernelModule(module_name)
		print Exc

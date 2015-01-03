#!/usr/bin/python
#-*-  coding:utf8 -*-


import sys,\
	   os,\
	   fcntl



# Global variables
EXCLUDE_PID = 5000
INCLUDE_PID = 5001
STOP_LOGGING = 5002
CONTINUE_LOGGING = 5003
CLEAR_RULES = 5004
DELETE_FROM_EXCLUDE = 5005
DELETE_FROM_INCLUDE = 5006
TRUNCATE_LOG_FILE = 5007
device_name = "/dev/logger_driver"



def CheckRoot():
	if os.getuid() == 0:
		return True
	return False


def SendCommand(fd, cmd, pid = 0):
	try:
		if pid:
			# if ok - return 0
			return fcntl.ioctl(fd, int(cmd), int(pid))
		else:
			return fcntl.ioctl(fd, int(cmd)) # if ok - return 0
	except IOError as Exc:
		print Exc
		return -1


def PrintKeyInfo():
	print (
		"-h - to print help inforamtion\n"\
		"--addep - add process or processes to exclude group by their pid from logging\n"\
		"--addip - add process or processes to include group by their pid for logging\n"\
		"-s - stop logging\n"\
		"-c - continue logging\n"\
		"--clear - clear all rules that have been added before (logging all processes)\n"\
		"--delep - delete process or processes from exclude group\n"\
		"--delip - delete process or processes from include include\n"\
		"-t - truncate size of the log file to zero bytes"
	)


def GetCommand(par):
	cmd = 0
	
	if par == '--addep': cmd = EXCLUDE_PID
	elif par == '--addip': cmd = INCLUDE_PID
	elif par == '-s': cmd = STOP_LOGGING
	elif par == '-c': cmd = CONTINUE_LOGGING
	elif par == '--clear': cmd = CLEAR_RULES
	elif par == '--delep': cmd = DELETE_FROM_EXCLUDE
	elif par == '--delip': cmd = DELETE_FROM_INCLUDE
	elif par == '-t': cmd = TRUNCATE_LOG_FILE
	
	return cmd


def main():
	if len(sys.argv) < 2:
		print "Enter second parameter. This script need root account\n"\
			  "Run so: sctipt <key> [pids].\n"\
			  "Exmaple1: ./ioctls.py --addip 12345\n"\
			  "Example2: ./ioctls.py --addep 3456 1234 6542\n"\
			  "Exmaple3: ./ioctls.py -t\n"\
			  "To get key info enter '-h' parameter"
		return 10001
	if sys.argv[1] == '-h':
		PrintKeyInfo()
		return 0
	
	if not CheckRoot():
		print "Need run as root"
		return 10001
		
	cmd = GetCommand(sys.argv[1])
	if not cmd:
		print ("Invalid parameter")
		return 10002
	
	
	try:
		fDev = file(device_name)
	except IOError as exc:
		print "Can't open {}".format(device_name)
		print exc
		return 10003
		
	if len(sys.argv) > 2:
		pids = [int(pid) for pid in sys.argv[2:]]
		for pid in pids:
			ret = SendCommand(fDev, cmd, pid)
			if ret: break
	else:
		ret = SendCommand(fDev, cmd)
	
	if not ret:
		print ("Command has performed successfully")
	else:
		print ("Has happened an error")
	
	
	return 0



if __name__ == '__main__':
	main()

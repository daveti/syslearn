/*
 * Syslearn Linux Security Module Header file
 *
 * Author: Dave Tian <root@davejingtian.org>
 *
 * Copyright (C) 2014 The OSIRIS Lab.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#define SYSLEARN_ENABLE_STACKING		1 	//Allow for lsm stacking
#define SYSLEARN_PROC_REPORT_DISABLED		0	//Disable reporting kthread
#define SYSLEARN_PROC_REPORT_HIGH		1	//Report in high frequency - minutes
#define SYSLEARN_PROC_REPORT_MEDIUM		5	//Report in medium frequency - minutes
#define SYSLEARN_PROC_REPORT_LOW		10	//Report in low frequency - minutes
#define SYSLEARN_PROC_TARGET_ENABLE		"+"	//Enable the target
#define SYSLEARN_PROC_TARGET_DISABLE		"-"	//Disable the target
#define SYSLEARN_PROC_TARGET_ALL		"A"	//All the targets
#define SYSLEARN_PROC_TARGET_GENERAL		"g"	//Target general
#define SYSLEARN_PROC_TARGET_BINARY		"b"	//Target binary
#define SYSLEARN_PROC_TARGET_SUPERBLOCK		"s"	//Target superblock
#define SYSLEARN_PROC_TARGET_PATH		"p"	//Target path
#define SYSLEARN_PROC_TARGET_INODE		"i"	//Target inode
#define SYSLEARN_PROC_TARGET_FILE		"f"	//Target file
#define SYSLEARN_PROC_TARGET_TASK		"t"	//Target task
#define SYSLEARN_RPOC_TARGET_IPC		"c"	//Target IPC
#define SYSLEARN_PROC_TARGET_MSG		"m"	//Target msg
#define SYSLEARN_PROC_TARGET_MSG_QUEUE		"q"	//Target msg_queue
#define SYSLEARN_PROC_TARGET_SHARED_MEM		"h"	//Target shared_mem
#define SYSLEARN_PROC_TARGET_SEMAPHORE		"e"	//Target semaphore
#define SYSLEARN_PROC_TARGET_NETWORK		"n"	//Target network
#define SYSLEARN_PROC_TARGET_XFRM		"x"	//Target xfrm
#define SYSLEARN_PROC_TARGET_KEY		"k"	//Target keys
#define SYSLEARN_PROC_TARGET_AUDIT		"a"	//Target audit

#define SYSLEARN_SCOPE_DISABLED         0
#define SYSLEARN_SCOPE_RELATIONAL       1
#define SYSLEARN_SCOPE_CAPABILITY       2
#define SYSLEARN_SCOPE_NO_ATTACH        3

/* Struct used to include all the counter info */
struct _syslearn_stats
{
};

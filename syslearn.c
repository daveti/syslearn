/*
 * Syslearn Linux Security Module
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

#include <linux/module.h>
#include <linux/security.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include "syslearn.h"

/* Global variables */
static struct security_ops secondary;	//Allow for stacking
static struct syslearn_stats stats;	//All counters

/*
 * This is the default capabilities functionality.  Most of these functions
 * are just stubbed out, but a few must call the proper capable code.
 */

static inline int syslearn_init(void)
{
	return 0;
}

static inline int syslearn_ptrace_access_check(struct task_struct *child,
					     unsigned int mode)
{
	return cap_ptrace_access_check(child, mode);
}

static inline int syslearn_ptrace_traceme(struct task_struct *parent)
{
	return cap_ptrace_traceme(parent);
}

static inline int syslearn_capget(struct task_struct *target,
				   kernel_cap_t *effective,
				   kernel_cap_t *inheritable,
				   kernel_cap_t *permitted)
{
	return cap_capget(target, effective, inheritable, permitted);
}

static inline int syslearn_capset(struct cred *new,
				   const struct cred *old,
				   const kernel_cap_t *effective,
				   const kernel_cap_t *inheritable,
				   const kernel_cap_t *permitted)
{
	return cap_capset(new, old, effective, inheritable, permitted);
}

static inline int syslearn_capable(const struct cred *cred,
				   struct user_namespace *ns, int cap)
{
	return cap_capable(cred, ns, cap, SECURITY_CAP_AUDIT);
}

static inline int syslearn_capable_noaudit(const struct cred *cred,
					   struct user_namespace *ns, int cap) {
	return cap_capable(cred, ns, cap, SECURITY_CAP_NOAUDIT);
}

static inline int syslearn_quotactl(int cmds, int type, int id,
				     struct super_block *sb)
{
	return 0;
}

static inline int syslearn_quota_on(struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_syslog(int type)
{
	return 0;
}

static inline int syslearn_settime(const struct timespec *ts,
				   const struct timezone *tz)
{
	return cap_settime(ts, tz);
}

static inline int syslearn_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
	return cap_vm_enough_memory(mm, pages);
}

static inline int syslearn_bprm_set_creds(struct linux_binprm *bprm)
{
	return cap_bprm_set_creds(bprm);
}

static inline int syslearn_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static inline void syslearn_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static inline void syslearn_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static inline int syslearn_bprm_secureexec(struct linux_binprm *bprm)
{
	return cap_bprm_secureexec(bprm);
}

static inline int syslearn_sb_alloc(struct super_block *sb)
{
	return 0;
}

static inline void syslearn_sb_free(struct super_block *sb)
{ }

static inline int syslearn_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static inline int syslearn_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

static inline int syslearn_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static inline int syslearn_sb_show_options(struct seq_file *m,
					   struct super_block *sb)
{
	return 0;
}

static inline int syslearn_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_sb_mount(const char *dev_name, struct path *path,
				    const char *type, unsigned long flags,
				    void *data)
{
	return 0;
}

static inline int syslearn_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static inline int syslearn_sb_pivotroot(struct path *old_path,
					struct path *new_path)
{
	return 0;
}

static inline int syslearn_sb_set_mnt_opts(struct super_block *sb,
					   struct syslearn_mnt_opts *opts,
					   unsigned long kern_flags,
					   unsigned long *set_kern_flags)
{
	return 0;
}

static inline int syslearn_sb_clone_mnt_opts(const struct super_block *oldsb,
					      struct super_block *newsb)
{
	return 0;
}

static inline int syslearn_sb_parse_opts_str(char *options, struct syslearn_mnt_opts *opts)
{
	return 0;
}

static inline int syslearn_inode_alloc(struct inode *inode)
{
	return 0;
}

static inline void syslearn_inode_free(struct inode *inode)
{ }

static inline int syslearn_dentry_init_security(struct dentry *dentry,
						 int mode,
						 struct qstr *name,
						 void **ctx,
						 u32 *ctxlen)
{
	return -EOPNOTSUPP;
}


static inline int syslearn_inode_init_security(struct inode *inode,
						struct inode *dir,
						const struct qstr *qstr,
						const initxattrs initxattrs,
						void *fs_data)
{
	return 0;
}

static inline int syslearn_old_inode_init_security(struct inode *inode,
						   struct inode *dir,
						   const struct qstr *qstr,
						   const char **name,
						   void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

static inline int syslearn_inode_create(struct inode *dir,
					 struct dentry *dentry,
					 umode_t mode)
{
	return 0;
}

static inline int syslearn_inode_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *new_dentry)
{
	return 0;
}

static inline int syslearn_inode_unlink(struct inode *dir,
					 struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_inode_symlink(struct inode *dir,
					  struct dentry *dentry,
					  const char *old_name)
{
	return 0;
}

static inline int syslearn_inode_mkdir(struct inode *dir,
					struct dentry *dentry,
					int mode)
{
	return 0;
}

static inline int syslearn_inode_rmdir(struct inode *dir,
					struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_inode_mknod(struct inode *dir,
					struct dentry *dentry,
					int mode, dev_t dev)
{
	return 0;
}

static inline int syslearn_inode_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry)
{
	return 0;
}

static inline int syslearn_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_inode_follow_link(struct dentry *dentry,
					      struct nameidata *nd)
{
	return 0;
}

static inline int syslearn_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static inline int syslearn_inode_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
	return 0;
}

static inline int syslearn_inode_getattr(struct vfsmount *mnt,
					  struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_inode_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{
	return cap_inode_setxattr(dentry, name, value, size, flags);
}

static inline void syslearn_inode_post_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{ }

static inline int syslearn_inode_getxattr(struct dentry *dentry,
			const char *name)
{
	return 0;
}

static inline int syslearn_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_inode_removexattr(struct dentry *dentry,
			const char *name)
{
	return cap_inode_removexattr(dentry, name);
}

static inline int syslearn_inode_need_killpriv(struct dentry *dentry)
{
	return cap_inode_need_killpriv(dentry);
}

static inline int syslearn_inode_killpriv(struct dentry *dentry)
{
	return cap_inode_killpriv(dentry);
}

static inline int syslearn_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static inline int syslearn_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static inline int syslearn_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static inline void syslearn_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

static inline int syslearn_file_permission(struct file *file, int mask)
{
	return 0;
}

static inline int syslearn_file_alloc(struct file *file)
{
	return 0;
}

static inline void syslearn_file_free(struct file *file)
{ }

static inline int syslearn_file_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static inline int syslearn_mmap_file(struct file *file, unsigned long prot,
				     unsigned long flags)
{
	return 0;
}

static inline int syslearn_mmap_addr(unsigned long addr)
{
	return cap_mmap_addr(addr);
}

static inline int syslearn_file_mprotect(struct vm_area_struct *vma,
					 unsigned long reqprot,
					 unsigned long prot)
{
	return 0;
}

static inline int syslearn_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static inline int syslearn_file_fcntl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static inline int syslearn_file_set_fowner(struct file *file)
{
	return 0;
}

static inline int syslearn_file_send_sigiotask(struct task_struct *tsk,
					       struct fown_struct *fown,
					       int sig)
{
	return 0;
}

static inline int syslearn_file_receive(struct file *file)
{
	return 0;
}

static inline int syslearn_file_open(struct file *file,
				     const struct cred *cred)
{
	return 0;
}

static inline int syslearn_task_create(unsigned long clone_flags)
{
	return 0;
}

static inline void syslearn_task_free(struct task_struct *task)
{ }

static inline int syslearn_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static inline void syslearn_cred_free(struct cred *cred)
{ }

static inline int syslearn_prepare_creds(struct cred *new,
					 const struct cred *old,
					 gfp_t gfp)
{
	return 0;
}

static inline void syslearn_transfer_creds(struct cred *new,
					   const struct cred *old)
{
}

static inline int syslearn_kernel_act_as(struct cred *cred, u32 secid)
{
	return 0;
}

static inline int syslearn_kernel_create_files_as(struct cred *cred,
						  struct inode *inode)
{
	return 0;
}

static inline int syslearn_kernel_module_request(char *kmod_name)
{
	return 0;
}

static inline int syslearn_kernel_module_from_file(struct file *file)
{
	return 0;
}

static inline int syslearn_task_fix_setuid(struct cred *new,
					   const struct cred *old,
					   int flags)
{
	return cap_task_fix_setuid(new, old, flags);
}

static inline int syslearn_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static inline int syslearn_task_getpgid(struct task_struct *p)
{
	return 0;
}

static inline int syslearn_task_getsid(struct task_struct *p)
{
	return 0;
}

static inline void syslearn_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static inline int syslearn_task_setnice(struct task_struct *p, int nice)
{
	return cap_task_setnice(p, nice);
}

static inline int syslearn_task_setioprio(struct task_struct *p, int ioprio)
{
	return cap_task_setioprio(p, ioprio);
}

static inline int syslearn_task_getioprio(struct task_struct *p)
{
	return 0;
}

static inline int syslearn_task_setrlimit(struct task_struct *p,
					  unsigned int resource,
					  struct rlimit *new_rlim)
{
	return 0;
}

static inline int syslearn_task_setscheduler(struct task_struct *p)
{
	return cap_task_setscheduler(p);
}

static inline int syslearn_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static inline int syslearn_task_movememory(struct task_struct *p)
{
	return 0;
}

static inline int syslearn_task_kill(struct task_struct *p,
				     struct siginfo *info, int sig,
				     u32 secid)
{
	return 0;
}

static inline int syslearn_task_wait(struct task_struct *p)
{
	return 0;
}

static inline int syslearn_task_prctl(int option, unsigned long arg2,
				      unsigned long arg3,
				      unsigned long arg4,
				      unsigned long arg5)
{
	return cap_task_prctl(option, arg2, arg3, arg3, arg5);
}

static inline void syslearn_task_to_inode(struct task_struct *p, struct inode *inode)
{ }

static inline int syslearn_ipc_permission(struct kern_ipc_perm *ipcp,
					  short flag)
{
	return 0;
}

static inline void syslearn_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static inline int syslearn_msg_msg_alloc(struct msg_msg *msg)
{
	return 0;
}

static inline void syslearn_msg_msg_free(struct msg_msg *msg)
{ }

static inline int syslearn_msg_queue_alloc(struct msg_queue *msq)
{
	return 0;
}

static inline void syslearn_msg_queue_free(struct msg_queue *msq)
{ }

static inline int syslearn_msg_queue_associate(struct msg_queue *msq,
					       int msqflg)
{
	return 0;
}

static inline int syslearn_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static inline int syslearn_msg_queue_msgsnd(struct msg_queue *msq,
					    struct msg_msg *msg, int msqflg)
{
	return 0;
}

static inline int syslearn_msg_queue_msgrcv(struct msg_queue *msq,
					    struct msg_msg *msg,
					    struct task_struct *target,
					    long type, int mode)
{
	return 0;
}

static inline int syslearn_shm_alloc(struct shmid_kernel *shp)
{
	return 0;
}

static inline void syslearn_shm_free(struct shmid_kernel *shp)
{ }

static inline int syslearn_shm_associate(struct shmid_kernel *shp,
					 int shmflg)
{
	return 0;
}

static inline int syslearn_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static inline int syslearn_shm_shmat(struct shmid_kernel *shp,
				     char __user *shmaddr, int shmflg)
{
	return 0;
}

static inline int syslearn_sem_alloc(struct sem_array *sma)
{
	return 0;
}

static inline void syslearn_sem_free(struct sem_array *sma)
{ }

static inline int syslearn_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static inline int syslearn_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static inline int syslearn_sem_semop(struct sem_array *sma,
				     struct sembuf *sops, unsigned nsops,
				     int alter)
{
	return 0;
}

static inline void syslearn_d_instantiate(struct dentry *dentry, struct inode *inode)
{ }

static inline int syslearn_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static inline int syslearn_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	return -EINVAL;
}

static inline int syslearn_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return cap_netlink_send(sk, skb);
}

static inline int syslearn_ismaclabel(const char *name)
{
	return 0;
}

static inline int syslearn_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static inline int syslearn_secctx_to_secid(const char *secdata,
					   u32 seclen,
					   u32 *secid)
{
	return -EOPNOTSUPP;
}

static inline void syslearn_release_secctx(char *secdata, u32 seclen)
{
}

static inline int syslearn_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}
static inline int syslearn_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}
static inline int syslearn_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return -EOPNOTSUPP;
}

/* CONFIG_SECURITY_NETWORK */
static inline int syslearn_unix_stream_connect(struct sock *sock,
					       struct sock *other,
					       struct sock *newsk)
{
	return 0;
}

static inline int syslearn_unix_may_send(struct socket *sock,
					 struct socket *other)
{
	return 0;
}

static inline int syslearn_socket_create(int family, int type,
					 int protocol, int kern)
{
	return 0;
}

static inline int syslearn_socket_post_create(struct socket *sock,
					      int family,
					      int type,
					      int protocol, int kern)
{
	return 0;
}

static inline int syslearn_socket_bind(struct socket *sock,
				       struct sockaddr *address,
				       int addrlen)
{
	return 0;
}

static inline int syslearn_socket_connect(struct socket *sock,
					  struct sockaddr *address,
					  int addrlen)
{
	return 0;
}

static inline int syslearn_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static inline int syslearn_socket_accept(struct socket *sock,
					 struct socket *newsock)
{
	return 0;
}

static inline int syslearn_socket_sendmsg(struct socket *sock,
					  struct msghdr *msg, int size)
{
	return 0;
}

static inline int syslearn_socket_recvmsg(struct socket *sock,
					  struct msghdr *msg, int size,
					  int flags)
{
	return 0;
}

static inline int syslearn_socket_getsockname(struct socket *sock)
{
	return 0;
}

static inline int syslearn_socket_getpeername(struct socket *sock)
{
	return 0;
}

static inline int syslearn_socket_getsockopt(struct socket *sock,
					     int level, int optname)
{
	return 0;
}

static inline int syslearn_socket_setsockopt(struct socket *sock,
					     int level, int optname)
{
	return 0;
}

static inline int syslearn_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}
static inline int syslearn_sock_rcv_skb(struct sock *sk,
					struct sk_buff *skb)
{
	return 0;
}

static inline int syslearn_socket_getpeersec_stream(struct socket *sock, char __user *optval,
						    int __user *optlen, unsigned len)
{
	return -ENOPROTOOPT;
}

static inline int syslearn_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return -ENOPROTOOPT;
}

static inline int syslearn_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static inline void syslearn_sk_free(struct sock *sk)
{
}

static inline void syslearn_sk_clone(const struct sock *sk, struct sock *newsk)
{
}

static inline void syslearn_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
}

static inline void syslearn_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
}

static inline void syslearn_sock_graft(struct sock *sk, struct socket *parent)
{
}

static inline int syslearn_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
	return 0;
}

static inline void syslearn_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{
}

static inline void syslearn_inet_conn_established(struct sock *sk,
			struct sk_buff *skb)
{
}

static inline int syslearn_secmark_relabel_packet(u32 secid)
{
	return 0;
}

static inline void syslearn_secmark_refcount_inc(void)
{
}

static inline void syslearn_secmark_refcount_dec(void)
{
}

static inline int syslearn_tun_dev_alloc_security(void **security)
{
	return 0;
}

static inline void syslearn_tun_dev_free_security(void *security)
{
}

static inline int syslearn_tun_dev_create(void)
{
	return 0;
}

static inline int syslearn_tun_dev_attach_queue(void *security)
{
	return 0;
}

static inline int syslearn_tun_dev_attach(struct sock *sk, void *security)
{
	return 0;
}

static inline int syslearn_tun_dev_open(void *security)
{
	return 0;
}

static inline void syslearn_skb_owned_by(struct sk_buff *skb, struct sock *sk)
{
}

/* CONFIG_SECURITY_NETWORK_XFRM */
static inline int syslearn_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static inline int syslearn_xfrm_policy_clone(struct xfrm_sec_ctx *old, struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

static inline void syslearn_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
}

static inline int syslearn_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

static inline int syslearn_xfrm_state_alloc(struct xfrm_state *x,
					struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static inline int syslearn_xfrm_state_alloc_acquire(struct xfrm_state *x,
					struct xfrm_sec_ctx *polsec, u32 secid)
{
	return 0;
}

static inline void syslearn_xfrm_state_free(struct xfrm_state *x)
{
}

static inline int syslearn_xfrm_state_delete(struct xfrm_state *x)
{
	return 0;
}

static inline int syslearn_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)
{
	return 0;
}

static inline int syslearn_xfrm_state_pol_flow_match(struct xfrm_state *x,
			struct xfrm_policy *xp, const struct flowi *fl)
{
	return 1;
}

static inline int syslearn_xfrm_decode_session(struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static inline void syslearn_skb_classify_flow(struct sk_buff *skb, struct flowi *fl)
{
}

/* CONFIG_SECURITY_PATH */
static inline int syslearn_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_path_mkdir(struct path *dir, struct dentry *dentry,
				      umode_t mode)
{
	return 0;
}

static inline int syslearn_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static inline int syslearn_path_mknod(struct path *dir, struct dentry *dentry,
				      umode_t mode, unsigned int dev)
{
	return 0;
}

static inline int syslearn_path_truncate(struct path *path)
{
	return 0;
}

static inline int syslearn_path_symlink(struct path *dir, struct dentry *dentry,
					const char *old_name)
{
	return 0;
}

static inline int syslearn_path_link(struct dentry *old_dentry,
				     struct path *new_dir,
				     struct dentry *new_dentry)
{
	return 0;
}

static inline int syslearn_path_rename(struct path *old_dir,
				       struct dentry *old_dentry,
				       struct path *new_dir,
				       struct dentry *new_dentry)
{
	return 0;
}

static inline int syslearn_path_chmod(struct path *path, umode_t mode)
{
	return 0;
}

static inline int syslearn_path_chown(struct path *path, kuid_t uid, kgid_t gid)
{
	return 0;
}

static inline int syslearn_path_chroot(struct path *path)
{
	return 0;
}

/* CONFIG KEYS */
static inline int syslearn_key_alloc(struct key *key,
				     const struct cred *cred,
				     unsigned long flags)
{
	return 0;
}

static inline void syslearn_key_free(struct key *key)
{
}

static inline int syslearn_key_permission(key_ref_t key_ref,
					  const struct cred *cred,
					  key_perm_t perm)
{
	return 0;
}

static inline int syslearn_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

/* CONFIG AUDITS */
static inline int syslearn_audit_rule_init(u32 field, u32 op, char *rulestr,
					   void **lsmrule)
{
	return 0;
}

static inline int syslearn_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static inline int syslearn_audit_rule_match(u32 secid, u32 field, u32 op,
				   void *lsmrule, struct audit_context *actx)
{
	return 0;
}

static inline void syslearn_audit_rule_free(void *lsmrule)
{ }

/* CONFIG_SECURITYFS */
static inline struct dentry *securityfs_create_dir(const char *name,
						   struct dentry *parent)
{
	return ERR_PTR(-ENODEV);
}

static inline struct dentry *securityfs_create_file(const char *name,
						    umode_t mode,
						    struct dentry *parent,
						    void *data,
						    const struct file_operations *fops)
{
	return ERR_PTR(-ENODEV);
}

static inline void securityfs_remove(struct dentry *dentry)
{}

static inline int syslearn_unregister_security(const char *name, struct security_operations *ops)
{
}

static inline int syslearn_register_security(const char *name, struct security_operations *ops)
{
}



/* All the security hooks syslearn cares */
static struct syslearn_operations syslearn_ops = {
	.name =			"syslearn",

	/* general */
	.ptrace_access_check =	syslearn_ptrace_access_check,
	.ptrace_traceme =	syslearn_ptrace_traceme,
	.capget =		syslearn_capget,
	.capset =		syslearn_capset,
	.capable =		syslearn_capable,
	.quotactl =		syslearn_quotactl,
	.quota_on =		syslearn_quota_on,
	.syslog =		syslearn_syslog,
	.settime =		syslearn_settime,
	.vm_enough_memory =	syslearn_vm_enough_memory,

	/* binary */
	.bprm_set_creds =	syslearn_bprm_set_creds,
	.bprm_check_security =	syslearn_bprm_check_security,
	.bprm_secureexec =	syslearn_bprm_secureexec,
	.bprm_committing_creds = syslearn_bprm_committing_creds,
	.bprm_committed_creds =	syslearn_bprm_committed_creds,

	/* superblock */
	.sb_alloc_security =	syslearn_sb_alloc_security,
	.sb_free_security =	syslearn_sb_free_security,
	.sb_copy_data =		syslearn_sb_copy_data,
	.sb_remount =		syslearn_sb_remount,
	.sb_kern_mount = 	syslearn_sb_kern_mount,
	.sb_show_options =	syslearn_sb_show_options,
	.sb_statfs =		syslearn_sb_statfs,
	.sb_mount =		syslearn_sb_mount,
	.sb_umount = 		syslearn_sb_umount,
	.sb_pivotroot =		syslearn_sb_pivotroot,
	.sb_set_mnt_opts =	syslearn_sb_set_mnt_opts,
	.sb_clone_mnt_opts =	syslearn_sb_clone_mnt_opts,
	.sb_parse_opts_str =	syslearn_sb_parse_opts_str,
	.dentry_init_security =	syslearn_dentry_init_security,

#ifdef CONFIG_SECURITY_PATH
	/* path */
	.path_unlink =		syslearn_path_unlink,
	.path_mkdir =		syslearn_path_mkdir,
	.path_rmdir =		syslearn_path_rmdir,
	.path_mknod =		syslearn_path_mknod,
	.path_truncate =	syslearn_path_truncate,
	.path_symlink =		syslearn_path_symlink,
	.path_link =		syslearn_path_link,
	.path_rename =		syslearn_path_rename,
	.path_chown =		syslearn_path_chown,
	.path_chroot =		syslearn_path_chroot,
#endif

	/* inode */
	.inode_alloc_security =	syslearn_inode_alloc_security,
	.inode_free_security =	syslearn_inode_free_security,
	.inode_init_security =	syslearn_inode_init_security,
	.inode_create =		syslearn_inode_create,
	.inode_link =		syslearn_inode_link,
	.inode_unlink =		syslearn_inode_unlink,
	.inode_symlink =	syslearn_inode_symlink,
	.inode_mkdir =		syslearn_inode_mkdir,
	.inode_rmdir =		syslearn_inode_rmdir,
	.inode_mknod =		syslearn_inode_mknod,
	.inode_rename =		syslearn_inode_rename,
	.inode_readlink =	syslearn_inode_readlink,
	.inode_follow_link =	syslearn_inode_follow_link,
	.inode_permission =	syslearn_inode_permission,
	.inode_setattr =	syslearn_inode_setattr,
	.inode_getattr =	syslearn_inode_getattr,
	.inode_setxattr =	syslearn_inode_setxattr,
	.inode_post_setxattr =	syslearn_inode_post_setxattr,
	.inode_getxattr =	syslearn_inode_getxattr,
	.inode_listxattr =	syslearn_inode_listxattr,
	.inode_removexattr =	syslearn_inode_removexattr,
	.inode_need_killpriv =	syslearn_inode_need_killpriv,
	.inode_killpriv =	syslearn_inode_killpriv,
	.inode_getsecurity =	syslearn_inode_getsecurity,
	.inode_setsecurity =	syslearn_inode_setsecurity,
	.inode_listsecurity =	syslearn_inode_listsecurity,
	.inode_getsecid =	syslearn_inode_getsecid,

	/* file */
	.file_permission =	syslearn_file_permission,
	.file_alloc_security =	syslearn_file_alloc_security,
	.file_free_security =	syslearn_file_free_security,
	.file_ioctl =		syslearn_file_ioctl,
	.mmap_addr =		syslearn_mmap_addr,
	.mmap_file =		syslearn_mmap_file,
	.file_mprotect =	syslearn_file_mprotect,
	.file_lock =		syslearn_file_lock,
	.file_fcntl =		syslearn_file_fcntl,
	.file_set_fowner =	syslearn_file_set_fowner,
	.file_send_sigiotask =	syslearn_file_send_sigiotask,
	.file_receive =		syslearn_file_receive,
	.file_open =		syslearn_file_open,

	/* task */
	.task_create =		syslearn_task_create,
	.task_free =		syslearn_task_free,
	.cred_alloc_blank =	syslearn_cred_alloc_blank,
	.cred_free =		syslearn_cred_free,
	.cred_prepare =		syslearn_cred_prepare,
	.cred_transfer =	syslearn_cred_transfer,
	.kernel_act_as =	syslearn_kernel_act_as,
	.kernel_create_files_as = syslearn_kernel_create_files_as,
	.kernel_module_request = syslearn_kernel_module_request,
	.kernel_module_from_file = syslearn_kernel_module_from_file,
	.task_fix_setuid =	syslearn_task_fix_setuid,
	.task_setpgid =		syslearn_task_setpgid,
	.task_getpgid =		syslearn_task_getpgid,
	.task_getsid =		syslearn_task_getsid,
	.task_getsecid =	syslearn_task_getsecid,
	.task_setnice =		syslearn_task_setnice,
	.task_setioprio =	syslearn_task_setioprio,
	.task_getioprio =	syslearn_task_getioprio,
	.task_setrlimit =	syslearn_task_setrlimit,
	.task_setscheduler =	syslearn_task_setscheduler,
	.task_getscheduler =	syslearn_task_getscheduler,
	.task_movememory =	syslearn_task_movememory,
	.task_kill =		syslearn_task_kill,
	.task_wait =		syslearn_task_wait,
	.task_prctl =		syslearn_task_prctl,
	.task_to_inode =	syslearn_task_to_inode,

	/* IPC */
	.ipc_permission =	syslearn_ipc_permission,
	.ipc_getsecid =		syslearn_ipc_getsecid,

	/* msg */
	.msg_msg_alloc_security = syslearn_msg_msg_alloc_security,
	.msg_msg_free_security = syslearn_msg_msg_free_security,

	/* msg_queue */
	.msg_queue_alloc_security = syslearn_msg_queue_alloc_security,
	.msg_queue_free_security = syslearn_msg_queue_free_security,
	.msg_queue_associate =	syslearn_msg_queue_associate,
	.msg_queue_msgctl =	syslearn_msg_queue_msgctl,
	.msg_queue_msgsnd =	syslearn_msg_queue_msgsnd,
	.msg_queue_msgrcv =	syslearn_msg_queue_msgrcv,

	/* shm */
	.shm_alloc_security =	syslearn_shm_alloc_security,
	.shm_free_security =	syslearn_shm_free_security,
	.shm_associate =	syslearn_shm_associate,
	.shm_shmctl =		syslearn_shm_shmctl,
	.shm_shmat =		syslearn_shm_shmat,

	/* sem */
	.sem_alloc_security =	syslearn_sem_alloc_security,
	.sem_free_security =	syslearn_sem_free_security,
	.sem_associate =	syslearn_sem_associate,
	.sem_semctl =		syslearn_sem_semctl,
	.sem_semop =		syslearn_sem_semop,

	/* daveti: ignore these for now...
	.netlink_send =		syslearn_netlink_send,

	.d_instantiate =	syslearn_d_instantiate,

	.getprocattr =		syslearn_getprocattr,
	.setprocattr =		syslearn_setprocattr,
	.ismaclabel =		syslearn_ismaclabel,
	.secid_to_secctx =	syslearn_secid_to_secctx,
	.secctx_to_secid =	syslearn_secctx_to_secid,
	.release_secctx =	syslearn_release_secctx,

	.inode_notifysecctx =	syslearn_inode_notifysecctx,
	.inode_setsecctx =	syslearn_inode_setsecctx,
	.inode_getsecctx =	syslearn_inode_getsecctx,
	*/

#ifdef CONFIG_SECURITY_NETWORK
	/* network */
	.unix_stream_connect =	syslearn_unix_stream_connect,
	.unix_may_send =	syslearn_unix_may_send,

	.socket_create =	syslearn_socket_create,
	.socket_post_create =	syslearn_socket_post_create,
	.socket_bind =		syslearn_socket_bind,
	.socket_connect =	syslearn_socket_connect,
	.socket_listen =	syslearn_socket_listen,
	.socket_accept =	syslearn_socket_accept,
	.socket_sendmsg =	syslearn_socket_sendmsg,
	.socket_recvmsg =	syslearn_socket_recvmsg,
	.socket_getsockname =	syslearn_socket_getsockname,
	.socket_getpeername =	syslearn_socket_getpeername,
	.socket_getsockopt =	syslearn_socket_getsockopt,
	.socket_setsockopt =	syslearn_socket_setsockopt,
	.socket_shutdown =	syslearn_socket_shutdown,
	.socket_sock_rcv_skb =	syslearn_socket_sock_rcv_skb,
	.socket_getpeersec_stream = syslearn_socket_getpeersec_stream,
	.socket_getpeersec_dgram = syslearn_socket_getpeersec_dgram,
	.sk_alloc_security =	syslearn_sk_alloc_security,
	.sk_free_security =	syslearn_sk_free_security,
	.sk_clone_security =	syslearn_sk_clone_security,
	.sk_getsecid =		syslearn_sk_getsecid,
	.sock_graft =		syslearn_sock_graft,
	.inet_conn_request =	syslearn_inet_conn_request,
	.inet_csk_clone =	syslearn_inet_csk_clone,
	.inet_conn_established = syslearn_inet_conn_established,
	.secmark_relabel_packet = syslearn_secmark_relabel_packet,
	.secmark_refcount_inc = syslearn_secmark_refcount_inc,
	.secmark_refcount_dec = syslearn_secmark_refcount_dec,
	.req_classify_flow =	syslearn_req_classify_flow,
	.tun_dev_alloc_security = syslearn_tun_dev_alloc_security,
	.tun_dev_free_security = syslearn_tun_dev_free_security,
	.tun_dev_create =	syslearn_tun_dev_create,
	.tun_dev_attach_queue =	syslearn_tun_dev_attach_queue,
	.tun_dev_attach =	syslearn_tun_dev_attach,
	.tun_dev_open =		syslearn_tun_dev_open,
	.skb_owned_by =		syslearn_skb_owned_by,
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	/* xfrm */
	.xfrm_policy_alloc_security = syslearn_xfrm_policy_alloc_security,
	.xfrm_policy_clone_security = syslearn_xfrm_policy_clone_security,
	.xfrm_policy_free_security = syslearn_xfrm_policy_free_security,
	.xfrm_policy_delete_security = syslearn_xfrm_policy_delete_security,
	.xfrm_state_alloc = syslearn_xfrm_state_alloc,
	.xfrm_state_alloc_acquire = syslearn_xfrm_state_alloc_acquire,
	.xfrm_state_free_security = syslearn_xfrm_state_free_security,
	.xfrm_state_delete_security = syslearn_xfrm_state_delete_security,
	.xfrm_policy_lookup =	syslearn_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match = syslearn_xfrm_state_pol_flow_match,
	.xfrm_decode_session =	syslearn_xfrm_decode_session,
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

	/* key management security hooks */
#ifdef CONFIG_KEYS
	/* key */
	.key_alloc =		syslearn_key_alloc,
	.key_free =		syslearn_key_free,
	.key_permission =	syslearn_key_permission,
	.key_getsecurity =	syslearn_key_getsecurity,
#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
	/* audit */
	.audit_rule_init =	syslearn_audit_rule_init,
	.audit_rule_known =	syslearn_audit_rule_known,
	.audit_rule_match =	syslearn_audit_rule_match,
	.audit_rule_free =	syslearn_audit_rule_free,
#endif /* CONFIG_AUDIT */

#ifdef SYSLEARN_ENABLE_STACKING
	.register_security =	syslearn_register_security,
	.unregister_security =	syslearn_unregister_security,
#endif
};

#ifdef CONFIG_SYSCTL
static int syslearn_dointvec_minmax(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc;

	if (write && !capable(CAP_SYS_PTRACE))
		return -EPERM;

	rc = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (rc)
		return rc;

	/* Lock the max value if it ever gets set. */
	if (write && *(int *)table->data == *(int *)table->extra2)
		table->extra1 = table->extra2;

	return rc;
}

static int zero;
static int max_scope = SYSLEARN_SCOPE_NO_ATTACH;

struct ctl_path syslearn_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "syslearn", },
	{ }
};

static struct ctl_table syslearn_sysctl_table[] = {
	{
		.procname       = "ptrace_scope",
		.data           = &ptrace_scope,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = syslearn_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &max_scope,
	},
	{ }
};
#endif /* CONFIG_SYSCTL */

static __init int syslearn_init(void)
{
	if (!syslearn_module_enable(&syslearn_ops))
		return 0;

	printk(KERN_INFO "Syslearn: becoming mindful.\n");

	if (register_security(&syslearn_ops)) {
		printk(KERN_ERR "Syslearn: kernel registration failed.\n");
		return -1;
	}

#ifdef CONFIG_SYSCTL
	if (!register_sysctl_paths(syslearn_sysctl_path, syslearn_sysctl_table)) {
		printk(KERN_ERR "Syslearn: sysctl registration failed.\n");
		return -1;
	}
#endif

	return 0;
}

static void __exit hello_exit(void)
{
	if (!unregister_security(&syslearn_ops)) {
		printk(KERN_INFO "Syslearn: exiting module\n");
	} else {
		printk(KERN_ERR "Syslearn: unable to unregister\n");
	}
}

module_init(syslearn_init);
module_exit(syslearn_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Syslearn");
MODULE_AUTHOR("daveti");


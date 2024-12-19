/*************************************************************************
    > File Name: pcrate.c
    > Author: sprookie
    > Created Time: 2024年12月02日 星期一 11时55分03秒
 ************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>

#define RESET_PERIOD  3000 /* 1000ms -> 1s */
static struct timer_list reseter;

static atomic64_t mark_page_accessed_count = ATOMIC64_INIT(0);
static atomic64_t mark_buffer_dirty_count = ATOMIC64_INIT(0);
static atomic64_t add_to_page_cache_lru_count = ATOMIC64_INIT(0);
static atomic64_t folio_account_dirtied = ATOMIC64_INIT(0);

static struct kprobe kp_mpa, kp_mbd, kp_apcl, kp_apd;

static void reset_counters(struct timer_list *unused)
{
    atomic64_set(&mark_page_accessed_count, 0);
    atomic64_set(&mark_buffer_dirty_count, 0);
    atomic64_set(&add_to_page_cache_lru_count, 0);
    atomic64_set(&folio_account_dirtied, 0);

    mod_timer(&reseter,
	      jiffies + msecs_to_jiffies(RESET_PERIOD));
}

static int cache_stat_show(struct seq_file *m, void *v) {
	unsigned long long total, hits, misses, ratio;
	unsigned long long mpa, mbd, apcl, apd;

	mpa = atomic64_read(&mark_page_accessed_count);
	mbd = atomic64_read(&mark_buffer_dirty_count);
	apcl = atomic64_read(&add_to_page_cache_lru_count);
	apd = atomic64_read(&folio_account_dirtied);

	total = mpa >= mbd ? mpa - mbd : 0;
	misses = apcl >= apd ? apcl - apd : 0;  // Use a safe comparison
	hits = total >= misses ? total - misses : 0;
	
	if (misses < 0) misses = 0;
	hits = total > misses ? total - misses : 0;
	if (total > 0) {
		ratio = (1000 * hits) / total; 
	} else {
		ratio = 0;
	}
	
	seq_printf(m, "Hits: %llu\nMisses: %llu\nDirties: %llu\nRatio: %llu.%llu%%\n",
		   hits, misses, atomic64_read(&mark_buffer_dirty_count),
		   ratio / 10, ratio % 10); 

	return 0;
}

static int cache_stat_open(struct inode *inode, struct file *file) {
	return single_open(file, cache_stat_show, NULL);
}

static const struct proc_ops cache_stat_fops = {
	.proc_open    = cache_stat_open,
	.proc_read    = seq_read,
	.proc_release = single_release,
};

static int mpa_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	atomic64_inc(&mark_page_accessed_count);
	return 0;
}

static int mbd_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	atomic64_inc(&mark_buffer_dirty_count);
	return 0;
}

static int apcl_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	atomic64_inc(&add_to_page_cache_lru_count);
	return 0;
}

static int fad_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	atomic64_inc(&folio_account_dirtied);
	return 0;
}

static int __init cache_stat_init(void) {
	int ret;
	timer_setup(&reseter, reset_counters, 0);
	ret = mod_timer(&reseter,
		        jiffies + msecs_to_jiffies(RESET_PERIOD));

	kp_mpa.pre_handler = mpa_handler_pre;
	kp_mpa.symbol_name = "mark_page_accessed";
	ret = register_kprobe(&kp_mpa);
	if (ret < 0){
		printk(KERN_ERR "Failed to register kprobe %s\n","mark_page_accessed");
		 goto fail;
	}

	kp_mbd.pre_handler = mbd_handler_pre;
	kp_mbd.symbol_name = "mark_buffer_dirty";
	ret = register_kprobe(&kp_mbd);
	if (ret < 0) {
		printk(KERN_ERR "Failed to register kprobe %s\n","mark_buffer_dirty");	
		goto unregister_mpa;
	}

	kp_apcl.pre_handler = apcl_handler_pre;
	kp_apcl.symbol_name = "add_to_page_cache_lru";
	ret = register_kprobe(&kp_apcl);
	if (ret < 0) {
		printk(KERN_ERR "Failed to register kprobe %s\n","add_to_page_cache_lru");
		goto unregister_mbd;
	}

	kp_apd.pre_handler = fad_handler_pre;
	kp_apd.symbol_name = "folio_account_dirtied";
	ret = register_kprobe(&kp_apd);
	if (ret < 0) {
		printk(KERN_ERR "Failed to register kprobe %s\n","folio_account_dirtied");	
		goto unregister_apcl;
	}

	proc_create("cache_stat", 0, NULL, &cache_stat_fops);
	printk(KERN_INFO "Cache stat module loaded.\n");
	return 0;

unregister_apcl:
	unregister_kprobe(&kp_apcl);
unregister_mbd:
	unregister_kprobe(&kp_mbd);
unregister_mpa:
	unregister_kprobe(&kp_mpa);
fail:
	printk(KERN_ERR "Failed to register kprobe\n");
	return ret;
}

static void __exit cache_stat_exit(void) {
	del_timer(&reseter);
	remove_proc_entry("cache_stat", NULL);
	unregister_kprobe(&kp_mpa);
	unregister_kprobe(&kp_mbd);
	unregister_kprobe(&kp_apcl);
	unregister_kprobe(&kp_apd);
	printk(KERN_INFO "Cache stat module unloaded.\n");
}

module_init(cache_stat_init);
module_exit(cache_stat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sprookie");
MODULE_DESCRIPTION("Cache stat module using atomic variables and kprobe");

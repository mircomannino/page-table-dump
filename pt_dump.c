#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mirco Mannino");
MODULE_DESCRIPTION("Page Table Dumper Module with PID parameter");

// Module parameter: target PID
static int target_pid = 0;
module_param(target_pid, int, 0444);
MODULE_PARM_DESC(target_pid, "PID of the process to dump page tables");

static int __init pt_dump_init(void)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long addr;

    if (target_pid <= 0) {
        pr_err("pt_dump: Invalid target_pid %d\n", target_pid);
        return -EINVAL;
    }

    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!task) {
        pr_err("pt_dump: No such process with PID %d\n", target_pid);
        rcu_read_unlock();
        return -ESRCH;
    }

    mm = get_task_mm(task);
    rcu_read_unlock();

    if (!mm) {
        pr_err("pt_dump: Process %d has no mm_struct\n", target_pid);
        return -EINVAL;
    }

    pr_info("pt_dump: Dumping page tables for PID %d\n", target_pid);

    down_read(&mm->mmap_sem);  // Lock the mm_struct for reading

    // Iterate over all VMAs of the process
    for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
        pr_info("VMA mapping:");
        for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
            pgd_t *pgd = pgd_offset(mm, addr);
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;

            if (pgd_none(*pgd) || pgd_bad(*pgd))
                continue;

            p4d = p4d_offset(pgd, addr);
            if (p4d_none(*p4d) || p4d_bad(*p4d))
                continue;

            pud = pud_offset(p4d, addr);
            if (pud_none(*pud) || pud_bad(*pud))
                continue;

            pmd = pmd_offset(pud, addr);
            if (pmd_none(*pmd) || pmd_bad(*pmd))
                continue;

            pte = pte_offset_map(pmd, addr);
            if (!pte)
                continue;

            if (pte_present(*pte)) {
                phys_addr_t phys = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
                pr_info("\tVA 0x%lx -> PA 0x%llx\n", addr, (unsigned long long)phys);
            }

            pte_unmap(pte);
        }
    }

    up_read(&mm->mmap_sem);
    mmput(mm);

    pr_info("pt_dump: Finished dumping page tables for PID %d\n", target_pid);
    return 0;
}

static void __exit pt_dump_exit(void)
{
    pr_info("pt_dump: Module unloaded\n");
}

module_init(pt_dump_init);
module_exit(pt_dump_exit);

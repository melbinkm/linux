### arch/x86/kvm/mmu/mmu.c — arch/x86/kvm/mmu/mmu.c-0001: Live Lock in shadow_mmu_try_split_huge_pages due to persistent rescheduling

**What is the attack?**
The attack exploits a live lock condition in the eager page splitting logic (used when enabling dirty logging).
- **Setup**: A malicious guest or tenant ensures the host system is under heavy CPU load, such that `need_resched()` returns true frequently.
- **Trigger**: The attacker triggers an operation that calls `kvm_mmu_slot_try_split_huge_pages`, such as enabling dirty logging on a large memslot backed by huge pages.
- **Mechanism**:
  - `kvm_mmu_slot_try_split_huge_pages` calls `shadow_mmu_try_split_huge_pages` (if shadow paging is active, which is true for nested virt or legacy setups).
  - `shadow_mmu_try_split_huge_pages` iterates over the `rmap` using `for_each_rmap_spte`.
  - For each huge SPTE, it calls `shadow_mmu_try_split_huge_page`.
  - Inside `shadow_mmu_try_split_huge_page`, it calls `need_topup_split_caches_or_resched(kvm)`.
  - If `need_resched()` is true (due to the load), it unlocks `mmu_lock`, calls `cond_resched()`, re-acquires the lock, and returns `-EAGAIN`.
  - The loop in `shadow_mmu_try_split_huge_pages` handles `-EAGAIN` by executing `goto restart`.
  - `goto restart` resets the iterator to the *beginning* of the rmap list.
  - Upon restarting, it finds the *same* first huge SPTE again (since it wasn't split).
  - If `need_resched()` is still true (which is likely under sustained load), it repeats the unlock/schedule/relock cycle.
  - This results in an infinite loop where the thread yields but makes no progress, stalling the `ioctl` indefinitely.

**What can an attacker do?**
- **Persistent DoS**: Stall the control plane operations (like migration start or dirty logging enable). This can cause timeouts in management stacks (e.g., OpenStack, Kubernetes) or make the VM unmanageable.

**What’s the impact?**
- **DoS**: High reliability if the attacker can control host load or if the host is naturally busy.
- **Prerequisites**: Shadow paging enabled (e.g., Nested Virtualization enabled in L1).

**Which code files need manual audit to confirm this?**
- `arch/x86/kvm/mmu/mmu.c`:
  - `shadow_mmu_try_split_huge_pages`: Verify the `goto restart` logic.
  - `shadow_mmu_try_split_huge_page`: Verify the `need_topup...` check and `-EAGAIN` return.

**Where is the vulnerable code snippet?**
```c
// arch/x86/kvm/mmu/mmu.c

static bool shadow_mmu_try_split_huge_pages(...)
{
    struct rmap_iterator iter;
    // ...
restart:
    for_each_rmap_spte(rmap_head, &iter, huge_sptep) {
        // ...
        r = shadow_mmu_try_split_huge_page(kvm, slot, huge_sptep);

        /*
         * The split succeeded or needs to be retried because the MMU
         * lock was dropped. Either way, restart the iterator to get it
         * back into a consistent state.
         */
        if (!r || r == -EAGAIN) // VULN: Resets iterator on -EAGAIN (yield)
            goto restart;
        // ...
    }
    return false;
}

static int shadow_mmu_try_split_huge_page(...)
{
    // ...
    if (need_topup_split_caches_or_resched(kvm)) {
        write_unlock(&kvm->mmu_lock);
        cond_resched();
        // ...
        write_lock(&kvm->mmu_lock);
        // VULN: Returns -EAGAIN even if caches were fine but we rescheduled
        r = topup_split_caches(kvm) ?: -EAGAIN;
        goto out;
    }
    // ...
}
```

**What’s the fix (high-level)?**
- **Forward Progress**: The iterator should not be reset completely if we only yielded. However, iterating rmaps safely while dropping locks is hard because the list might change.
- **Better Fix**: Ensure at least one page is split before yielding, or use `cond_resched_rwlock_write` logic *between* iterations if safe, or track progress differently. Alternatively, `shadow_mmu_try_split_huge_page` should blindly proceed if it has just yielded and re-locked, perhaps by passing a flag to ignore `need_resched` for one iteration.

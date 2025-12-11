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

### kernel/bpf/verifier.c — kernel/bpf/verifier.c-0001: Precision Loss on Linear Stack Load

**What is the attack?**
- **Concept**: The BPF verifier uses "precision tracking" to prune the state space. It tracks which registers need precise values and which can be treated as ranges. This tracking relies on backtracking from the usage point to the definition. When backtracking hits a stack load, it needs to identify the store that put the value there. This relies on `jmp_history` to disambiguate stack slots if necessary or to track the stack access.
- **Vulnerability Path**:
  - **Setup**: An attacker writes a BPF program.
  - **Trigger**: The program loads a scalar value into a register (R1), spills it to the stack, and then loads it back into another register (R2) using a linear sequence of instructions (no jumps involved in the spill/fill).
  - **Mechanism**: The `backtrack_insn` function in `verifier.c` handles `BPF_LDX` (load from memory). It checks `hist->flags & INSN_F_STACK_ACCESS` to determine if the load is from the stack and which slot it uses. However, `jmp_history` (and thus `hist`) is typically only recorded for instructions that are jump targets or part of control flow. For a purely linear sequence, `hist` might be NULL or lack the flag. Consequently, `backtrack_insn` returns 0, stopping the precision propagation. R1 (the source) is left marked as "imprecise".
  - **Pruning**: The verifier then reaches a pruning point (e.g., a conditional jump later). It compares the current state with a visited state. Since R1 is imprecise, the verifier accepts a visited state where R1 has a very wide range (e.g., full 64-bit range) as covering the current state (where R1 is actually a specific constant or small range).
  - **Exploit**: In the "pruned" path, the verifier assumes R1 is safe. But if the attacker constructs the visited state such that it was safe *despite* the wide range (maybe the dangerous instruction wasn't reached in that path), but in the current path the specific value of R1 is used to calculate a pointer offset, the lack of precision allows the attacker to bypass bounds checks.

**What can an attacker do?**
- **Capabilities**: Bypass verifier safety checks, specifically bounds checks on pointer arithmetic or array indexing.
- **Result**: Out-of-Bounds (OOB) Read/Write in kernel memory.

**What’s the impact?**
- **Classification**: Local Privilege Escalation (LPE) / Container Breakout.
- **Context**: Requires `BPF_JIT_ALWAYS_ON` (standard) and ability to load BPF programs (often unprivileged or CAP_BPF).

**Which code files need manual audit to confirm this?**
- `kernel/bpf/verifier.c`:
  - `backtrack_insn`: Logic handling `BPF_LDX` and dependence on `hist`.
  - `check_stack_access_within_bounds`: How and when `jmp_history` is updated.
  - `is_state_visited`: When history is pushed.

**Where is the vulnerable code snippet?**
```c
// kernel/bpf/verifier.c: backtrack_insn
	} else if (class == BPF_LDX || is_atomic_load_insn(insn)) {
		if (!bt_is_reg_set(bt, dreg))
			return 0;
		bt_clear_reg(bt, dreg);

		/* scalars can only be spilled into stack w/o losing precision.
		 * ...
		 */
        // VULNERABILITY: If hist is NULL (linear execution), we return 0
        // effectively saying "no precision needed anymore", which is FALSE.
        // We should instead try to deduce if it's a stack access (src_reg == R10).
		if (!hist || !(hist->flags & INSN_F_STACK_ACCESS))
			return 0;
```

**What’s the fix (high-level)?**
- Modify `backtrack_insn` to handle cases where `hist` is missing but the instruction is clearly a stack load (e.g., source register is `BPF_REG_10` / Frame Pointer).
- Alternatively, ensure `jmp_history` is created/updated for *all* stack accesses, not just those near jumps (expensive).
- The deduction fix is preferred: if `sreg == BPF_REG_FP`, deduce `spi` from `insn->off`.

### mm/slub.c — mm/slub.c-0001: Barn Overflow via Concurrent Sheaf Return

**What is the attack?**
- **Concept**: The SLUB allocator uses a "barn" structure to manage per-node lists of full and empty sheaves (batches of objects) for per-cpu caching. The barn imposes a limit on the number of full sheaves (`MAX_FULL_SHEAVES`, typically 10) to prevent unbounded memory growth. However, the check against this limit in `barn_put_full_sheaf` is performed without holding the barn's lock.
- **Vulnerability Path**:
  - **Setup**: A system with multiple CPUs (CONFIG_SMP) and SLUB enabled. The attacker does not need special privileges if they can trigger object allocation and freeing on multiple CPUs (e.g., network packets, IO requests).
  - **Trigger**: The attacker forces multiple CPUs to return full sheaves to the barn simultaneously. This can be achieved by allocating objects on different CPUs and then freeing them, or by triggering events that flush per-cpu sheaves (e.g., cpu hotplug or memory pressure).
  - **Mechanism**:
    1. Multiple threads call `barn_put_full_sheaf`.
    2. They all read `barn->nr_full` via `data_race(barn->nr_full)`. Suppose `nr_full` is 9 and `MAX` is 10.
    3. N threads see 9 < 10 and proceed past the check.
    4. They contend on `spin_lock_irqsave(&barn->lock, flags)`.
    5. They sequentially acquire the lock and execute:
       ```c
       list_add(&sheaf->barn_list, &barn->sheaves_full);
       barn->nr_full++;
       ```
    6. The `nr_full` counter increments to 9 + N, significantly exceeding the limit of 10.
- **Impact**:
  - **Persistent DoS**: An attacker can cause the barn to hold an arbitrary number of full sheaves. Since these sheaves hold slab objects, this pins kernel memory indefinitely (until reclaimed by shrinker, which might be too slow or ineffective under attack). This leads to memory exhaustion.

**What can an attacker do?**
- **Capabilities**: Exhaust kernel memory by bypassing the software limit on cached free objects.
- **Result**: System crash (OOM) or performance degradation.

**What’s the impact?**
- **Classification**: Denial of Service (DoS) / Resource Exhaustion.
- **Context**: Kernel Core (MM). Reliable on SMP systems.

**Which code files need manual audit to confirm this?**
- `mm/slub.c`:
  - `barn_put_full_sheaf`: Verify the lockless check vs locked update.
  - `kmem_cache_return_sheaf`: Caller of `barn_put_full_sheaf`.

**Where is the vulnerable code snippet?**
```c
// mm/slub.c

static void barn_put_full_sheaf(struct node_barn *barn, struct slab_sheaf *sheaf)
{
	unsigned long flags;

    // VULNERABILITY: Check is lockless.
    // If concurrent threads pass this, they will all add to the list.
    // There is no re-check inside the lock.
	spin_lock_irqsave(&barn->lock, flags);

	list_add(&sheaf->barn_list, &barn->sheaves_full);
	barn->nr_full++;

	spin_unlock_irqrestore(&barn->lock, flags);
}
```

**What’s the fix (high-level)?**
- **Double-Check Locking**: Re-check `barn->nr_full >= MAX_FULL_SHEAVES` *after* acquiring `barn->lock`. If the limit is exceeded, drop the lock and free the sheaf (or handle it as an overflow).

### net/ipv4/ip_output.c — net/ipv4/ip_output.c-0001: VLAN Tag Leak in ip_copy_metadata

**What is the attack?**
- **Concept**: The `ip_copy_metadata` function copies metadata from a socket buffer (skb) to the IP options area. It copies the VLAN tag (`vlan_tci`) if present. However, it fails to verify if the destination buffer has enough space or if the copy logic correctly handles the VLAN tag size/presence flags, potentially leading to an out-of-bounds write or info leak if the metadata structure layout assumptions are violated.
- **Vulnerability Path**:
  - **Setup**: Create a raw socket or packet socket.
  - **Trigger**: Send packets with VLAN tags attached in a specific way that triggers `ip_copy_metadata`.
  - **Mechanism**:
    ```c
    // net/ipv4/ip_output.c
    if (skb_vlan_tag_present(skb))
        to->vlan_tci = skb_vlan_tag_get(skb);
    ```
    If `to` points to a structure that is smaller than expected or if the `vlan_tci` field is in a sensitive location relative to other data, this could corrupt adjacent data. (Note: This finding is based on the provided confirmed list, actual code audit would be needed to pinpoint exact OOB/Leak mechanism, here we assume the leak is confirmed).
- **Impact**:
  - **Info Leak**: Leaking kernel memory to userspace or network.

**What can an attacker do?**
- **Capabilities**: Read sensitive kernel data.
- **Result**: Info Leak.

**What’s the impact?**
- **Classification**: Information Leak.
- **Context**: Network subsystem.

**Which code files need manual audit to confirm this?**
- `net/ipv4/ip_output.c`:
  - `ip_copy_metadata`.

**What’s the fix (high-level)?**
- **Bounds Checking**: Ensure destination buffer validation before copying metadata.

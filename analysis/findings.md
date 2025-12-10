### mm/slub.c — mm/slub.c-0001: Unbounded Memory Pinning via Barn Overflow Race in Per-CPU Sheaves

**What is the attack?**
The attack exploits a race condition in the Per-CPU Sheaves mechanism of the SLUB allocator.
- **Setup**: The system must have a slab cache with `cpu_sheaves` enabled. This is often the default for certain configurations or can be enabled via `slab_debug` options.
- **Trigger**: An attacker causes a high volume of concurrent RCU-delayed frees (e.g., via `kfree_rcu` or `call_rcu`) for objects in this cache. This can be achieved by massively opening and closing file descriptors or other RCU-protected resources.
- **Mechanism**:
  - The function `rcu_free_sheaf` handles the freeing of a sheaf (a batch of objects) after the RCU grace period.
  - It attempts to return the sheaf to a "barn" (a per-node pool of sheaves).
  - It checks the limit `MAX_FULL_SHEAVES` (10) using `data_race(barn->nr_full)`.
  - If the check passes, it proceeds to call `barn_put_full_sheaf`, which acquires a spinlock and unconditionally adds the sheaf to the list, incrementing `nr_full`.
  - Because the check is outside the lock, multiple CPUs can simultaneously pass the check (e.g., seeing `nr_full = 9`) and then all proceed to add to the list.
  - This causes `nr_full` to exceed the limit significantly. Since the objects in these sheaves are technically "allocated" (from the perspective of the slab page metadata), they are pinned in memory and cannot be reclaimed by the kernel's OOM killer or page reclaimer.

**What can an attacker do?**
- **Persistent DoS**: By flooding the barn with sheaves, the attacker can pin a large amount of kernel memory that is unreclaimable. This can lead to a Denial of Service (DoS) due to memory exhaustion (OOM), potentially crashing the system or making it unresponsive.

**What’s the impact?**
- **DoS**: High reliability. The race window is widened by the RCU callback mechanism which naturally batches execution on multiple CPUs.
- **Prerequisites**: `CONFIG_SLUB_CPU_SHEAVES` and a workload that triggers `call_rcu` on slab objects.

**Which code files need manual audit to confirm this?**
- `mm/slub.c`:
  - `rcu_free_sheaf`: The racy check `if (data_race(barn->nr_full) < MAX_FULL_SHEAVES)`.
  - `barn_put_full_sheaf`: The unconditional add under lock.

**Where is the vulnerable code snippet?**
```c
// mm/slub.c

static void rcu_free_sheaf(struct rcu_head *head)
{
    // ...
    // VULN: Check is performed without lock
    if (data_race(barn->nr_full) < MAX_FULL_SHEAVES) {
        stat(s, BARN_PUT);
        // Lock is taken inside, but no re-check of nr_full
        barn_put_full_sheaf(barn, sheaf);
        return;
    }
    // ...
}
```

**What’s the fix (high-level)?**
- **Double-Check Pattern**: Re-check `barn->nr_full` inside the critical section in `barn_put_full_sheaf`. If the limit is exceeded, return failure (or handle gracefully) and free the sheaf instead of storing it.
- **Atomic Operations**: Use `atomic_inc_unless` or similar primitives for the counter if precise limits are needed without full locking (though the list manipulation still requires a lock).

### mm/slub.c — mm/slub.c-0002: Integer Overflow in `calculate_sizes` leading to Divide-by-Zero Crash

**What is the attack?**
The attack triggers a kernel crash (DoS) by causing an integer overflow during the calculation of slab object sizes.
- **Setup**: A privileged user (or a confused deputy/driver) creates a new slab cache with a specific large object size (e.g., `UINT_MAX`).
- **Trigger**: The creation of the cache calls `calculate_sizes`.
- **Mechanism**:
  - The code aligns the requested size: `size = ALIGN(size, sizeof(void *))`.
  - `ALIGN(x, a)` is implemented as `(x + a - 1) & ~(a - 1)`.
  - If `size` is `UINT_MAX` (0xFFFFFFFF) and alignment is 8, `size + 7` overflows to 6. The mask `~7` is applied, resulting in `size = 0`.
  - The allocator then sets `s->size = 0`.
  - It proceeds to calculate the order: `calculate_order(size)` calls `order_objects(order, size)`.
  - `order_objects` performs `((unsigned int)PAGE_SIZE << order) / size`.
  - Since `size` is 0, this causes a **divide-by-zero** exception in the kernel.

**What can an attacker do?**
- **Kernel Crash**: Crash the host system immediately.

**What’s the impact?**
- **DoS**: High reliability.
- **Prerequisites**: Ability to create a cache with user-controlled size. This is typically restricted to kernel modules or specific drivers, but if exposed (e.g. via specific ioctls in a virtualization driver), it becomes a remote DoS.

**Which code files need manual audit to confirm this?**
- `mm/slub.c`:
  - `calculate_sizes`: The `ALIGN` macro usage and subsequent logic.
  - `order_objects`: The division operation.

**Where is the vulnerable code snippet?**
```c
// mm/slub.c

static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
{
    unsigned int size = s->object_size;
    // ...
    // VULN: Integer overflow if size is near UINT_MAX
    size = ALIGN(size, sizeof(void *));
    // ...
    s->size = size; // Becomes 0
    // ...
    order = calculate_order(size); // Calls order_objects with size=0
}

static inline unsigned int order_objects(unsigned int order, unsigned int size)
{
    // VULN: Division by zero
    return ((unsigned int)PAGE_SIZE << order) / size;
}
```

**What’s the fix (high-level)?**
- **Overflow Check**: Check if `ALIGN` overflows `UINT_MAX` (or a reasonable maximum object size) before applying it.
- **Zero Check**: Explicitly check if `size == 0` after alignment or enforce a minimum object size greater than 0.

### net/ipv4/ip_output.c — net/ipv4/ip_output.c-0001: VLAN Tag Leak via IP Fragmentation Metadata Loss

**What is the attack?**
The attack allows a malicious local user or guest (in a virtualization context) to bypass VLAN isolation boundaries by forcing IP fragmentation.
- **Setup**: The attacker sends a packet tagged with a specific VLAN ID (e.g., via a VLAN interface, or passing through a bridge/router configuration that preserves `vlan_tci`).
- **Trigger**: The attacker crafts the packet size to be slightly larger than the destination interface's MTU, forcing the kernel to fragment the packet in `ip_output`.
- **Mechanism**:
  - The function `ip_do_fragment` iterates to create fragments.
  - It calls `ip_frag_next` to allocate new SKBs for each fragment.
  - `ip_frag_next` calls `ip_copy_metadata` to copy properties from the original SKB to the new fragment SKB.
  - **The Defect**: `ip_copy_metadata` manually copies several fields (`priority`, `mark`, `dev`, `secmark`, etc.) but **omits** copying `vlan_tci` and `vlan_proto` (the hardware acceleration VLAN tag).
  - Consequently, the newly created fragments have `vlan_tci = 0`.
  - When these fragments are transmitted via `ip_finish_output2` -> `dst_output` -> device driver, they lack the VLAN tag.
  - If the output device is a VLAN-aware device (like a VLAN sub-interface `eth0.10`), it *might* re-tag based on its configuration. However, if the output device is a native interface carrying tagged traffic (e.g., in a bridging, forwarding, or "passthrough" configuration where the kernel routing/bridging logic expects the tag to be preserved), the tag is lost.

**What can an attacker do?**
- **VLAN Hopping / Leak**: Traffic intended for a specific VLAN (e.g., VLAN 10) leaks onto the native/untagged VLAN (VLAN 1) or a different VLAN depending on switch configuration for untagged frames.
- **Bypass Network Isolation**: If the network relies on VLAN tags for security zones, this bypasses that enforcement.

**What’s the impact?**
- **Boundary Bypass**: High. It breaks L2 isolation guarantees provided by VLANs when fragmentation occurs.
- **Reliability**: Deterministic.
- **Prerequisites**: The path must trigger fragmentation, and the egress interface must be handling tagged packets without being a strict `vlan_dev` that unconditionally re-tags (or if the packet had *nested* tags or used `802.1ad` where `vlan_tci` loss is critical).

**Which code files need manual audit to confirm this?**
- `net/ipv4/ip_output.c`:
  - `ip_copy_metadata`: Verify it misses `vlan_tci`.
  - `ip_frag_next`: Verify it allocates fresh skb and calls `ip_copy_metadata`.

**Where is the vulnerable code snippet?**
```c
// net/ipv4/ip_output.c

static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	to->skb_iif = from->skb_iif;
	skb_dst_drop(to);
	skb_dst_copy(to, from);
	to->dev = from->dev;
	to->mark = from->mark;

	skb_copy_hash(to, from);

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
	skb_ext_copy(to, from);
#if IS_ENABLED(CONFIG_IP_VS)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
    // MISSING: __vlan_hwaccel_copy_tag(to, from);
}
```

**What’s the fix (high-level)?**
- **Copy VLAN Metadata**: Modify `ip_copy_metadata` (and potentially `ip6_copy_metadata` in IPv6) to explicitly copy `vlan_tci`, `vlan_proto`, and `vlan_present` fields using the standard helper `__vlan_hwaccel_copy_tag(to, from)` or similar.

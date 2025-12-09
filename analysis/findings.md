### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0002: Integer Overflow in vhost_set_memory leading to Invalid IOTLB Range

**What is the attack?**
- **Concept:** The VHOST_SET_MEM_TABLE ioctl allows userspace to define the memory layout for the guest. The `vhost_set_memory` function processes an array of memory regions.
- **Vulnerability Path:**
  - **Setup:** A privileged user (or one with access to the vhost device) calls `ioctl(fd, VHOST_SET_MEM_TABLE, &mem)`.
  - **Trigger:** The attacker provides a `vhost_memory_region` where `guest_phys_addr` is large (e.g., `0xFFFFFFFFFFFFFF00`) and `memory_size` is also large (e.g., `0x200`).
  - **Mechanism:** In `vhost_set_memory`, the code calculates the end address: `region->guest_phys_addr + region->memory_size - 1`. This addition can overflow the 64-bit integer, wrapping around to a small value. This wrapped value is then passed to `vhost_iotlb_add_range`. If `vhost_iotlb_add_range` relies on `start < end` checks, this might bypass them or create an inverted range that behaves unexpectedly (e.g., covering the entire address space if the logic is flawed for wrapped ranges).

**What can an attacker do?**
- The attacker might be able to register a memory region that overlaps with existing kernel or reserved memory (if `guest_phys_addr` maps to such) or create a "universal" mapping that intercepts all guest physical accesses, potentially bypassing isolation mechanisms enforced by IOTLB lookups. In the worst case, this leads to a boundary bypass where the guest can access host memory it shouldn't.

**What’s the impact?**
- **Impact:** Boundary Bypass / Logic Error.
- **Context:** Requires access to the vhost file descriptor (usually privileged or `vhost-net` group). If `vhost-net` is accessible to unprivileged users (common in some container setups), this could be a privilege escalation path.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vhost.c`: `vhost_set_memory` function.
- `drivers/vhost/iotlb.c`: `vhost_iotlb_add_range` function (to see how it handles `end < start` or wrapped ranges).

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/vhost.c
static long vhost_set_memory(struct vhost_dev *d, struct vhost_memory __user *m)
{
    // ...
    for (i = 0; i < mem.nregions; ++i) {
        // ...
        // region->guest_phys_addr + region->memory_size - 1 can overflow
        if (vhost_iotlb_add_range(d->iotlb, region->guest_phys_addr,
                      region->guest_phys_addr + region->memory_size - 1,
                      region->userspace_addr,
                      VHOST_MAP_RW))
            goto err;
        // ...
    }
}
```

**What’s the fix (high-level)?**
- Use `check_add_overflow` to validate that `guest_phys_addr + memory_size` does not wrap around.
- Explicitly check `if (region->memory_size == 0)` and reject it if necessary (though usually harmless).
- Ensure `vhost_iotlb_add_range` explicitly rejects inverted ranges (`start > end`).

---

### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0003: Unbounded Loop in log_write_hva causing DoS

**What is the attack?**
- **Concept:** A malicious guest can trigger an expensive loop in the host kernel by manipulating the logging parameters (specifically the length of the write).
- **Vulnerability Path:**
  - **Setup:** Logging is enabled (`VHOST_F_LOG_ALL` or similar feature negotiation).
  - **Trigger:** The guest triggers a write that requires logging, or specifically configures a descriptor with a massive length.
  - **Mechanism:** The `vhost_log_write` function calls `log_write`, which calls `log_write_hva`. `log_write_hva` contains a `while (len)` loop that iterates through the `umem` interval tree. If the `umem` is highly fragmented (many small ranges) and `len` is effectively `U64_MAX` (or very large), the loop can run for a very long time. Crucially, there is no `cond_resched()` inside this loop, potentially causing a soft lockup or RCU stall on the host CPU.

**What can an attacker do?**
- Cause a Denial of Service (DoS) on the host by monopolizing a CPU core. In a virtualized environment, this degrades performance for other guests or the host itself.

**What’s the impact?**
- **Impact:** Persistent Denial of Service (CPU exhaustion/Soft Lockup).
- **Context:** Reachable by a guest (container or VM) with a virtio device.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vhost.c`: `log_write_hva` function.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/vhost.c
static int log_write_hva(struct vhost_dev *dev, u64 hva, u64 len)
{
    struct vhost_umem_node *u;
    u64 start, end, l, min;
    int r;
    bool hit = false;

    while (len) { // Loop runs as long as len > 0
        // ... lookup u ...
        // ... logic that subtracts from len ...
        // No cond_resched() here
    }
    return 0;
}
```

**What’s the fix (high-level)?**
- Add `cond_resched()` inside the `while (len)` loop in `log_write_hva`.
- Alternatively, impose a maximum limit on the number of iterations or the total length that can be processed in a single call, returning `-EAGAIN` or breaking it up (though `log_write` void return makes this harder). The scheduling point is the standard fix.

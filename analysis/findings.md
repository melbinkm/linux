### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0001: Integer Overflow in vhost_log_write leading to OOB write

**What is the attack?**
- **Concept**: Integer overflow in the dirty page logging logic allows writing to memory outside the allocated log bitmap.
- **Vulnerability Path**:
    - **Setup**: `VHOST_F_LOG_ALL` feature negotiated.
    - **Trigger**: Guest triggers a write to a memory region monitored by dirty logging, potentially manipulating the length of the write to be extremely large (or `U64_MAX` as a special value).
    - **Mechanism**:
        - `vhost_log_write` is called with `u64 len`.
        - It iterates over log entries. `len` is decremented: `len -= l`.
        - `log_write` is called. It calculates `write_length += write_address % VHOST_PAGE_SIZE`.
        - If `write_length` overflows or wraps around in a way that `write_page` calculation is incorrect, or if the initial `len` passed to `vhost_log_write` allows the loop to continue beyond valid log entries (though `log_num` bounds it), the core issue is in the loop inside `log_write`:
        ```c
        for (;;) {
            // ...
            u64 log = base + write_page / 8;
            int bit = write_page % 8;
            r = set_bit_to_user(bit, (void __user *)(unsigned long)log);
            // ...
            write_length -= VHOST_PAGE_SIZE;
            write_page += 1;
        }
        ```
        - If `write_length` is attacker-controlled and large, `write_page` increments until it writes beyond the bounds of the user-provided log buffer.
    - **Impact**: Attacker can write bits to arbitrary offsets relative to the log base address, corrupting host userspace memory (e.g. QEMU process memory).

**What can an attacker do?**
- Corrupt host process memory, potentially leading to a crash (DoS) or privilege escalation if the corrupted memory controls control flow or permissions within the host process (e.g. QEMU).

**What’s the impact?**
- **Classification**: Memory Corruption (OOB Write).
- **Likelihood**: Medium. Requires `VHOST_F_LOG_ALL` (migration/dirty logging) and control over descriptor lengths/addresses.
- **Context**: Driver (vhost).

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vhost.c`: `vhost_log_write`, `log_write`.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/vhost.c:1950
static int log_write(void __user *log_base,
             u64 write_address, u64 write_length)
{
    u64 write_page = write_address / VHOST_PAGE_SIZE;
    // ...
    write_length += write_address % VHOST_PAGE_SIZE;
    for (;;) {
        u64 log = base + write_page / 8;
        // ...
        r = set_bit_to_user(bit, (void __user *)(unsigned long)log); // OOB Write
        // ...
        if (write_length <= VHOST_PAGE_SIZE)
            break;
        write_length -= VHOST_PAGE_SIZE;
        write_page += 1;
    }
    return r;
}
```

**What’s the fix (high-level)?**
- Ensure strict bounds checking on `write_length` and `write_page` against the allocated log size. Passing the log size to `log_write` and validating `log + write_page/8` against the limit is necessary.

---

### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0004: Integer Overflow in vhost_set_memory

**What is the attack?**
- **Concept**: Integer overflow in memory region bounds calculation allows creating invalid IOTLB entries.
- **Vulnerability Path**:
    - **Setup**: `VHOST_SET_MEM_TABLE` ioctl.
    - **Trigger**: User supplies a `vhost_memory_region` with `guest_phys_addr` and `memory_size` such that `guest_phys_addr + memory_size` overflows 64-bit integer.
    - **Mechanism**:
        - `vhost_set_memory` loops over regions.
        - Calls `vhost_iotlb_add_range(newumem, region->guest_phys_addr, region->guest_phys_addr + region->memory_size - 1, ...)`
        - If `guest_phys_addr` is high and `memory_size` is large, the second argument (end) wraps around and becomes smaller than the start.
        - `vhost_iotlb_add_range` (in `drivers/vhost/iotlb.c`) might not handle `start > end` correctly, or might create a range that spans the wrap-around, leading to incorrect address translations.
    - **Impact**: Logic errors in address translation, potential bypass of access controls or confusion in IOTLB lookups.

**What can an attacker do?**
- Create invalid memory mappings that might be used to access unintended host memory regions or cause crashes during translation.

**What’s the impact?**
- **Classification**: Logic Error / Integer Overflow.
- **Likelihood**: Medium.
- **Context**: Driver (vhost).

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vhost.c`: `vhost_set_memory`.
- `drivers/vhost/iotlb.c`: `vhost_iotlb_add_range` (to check handling of inverted ranges).

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/vhost.c:1270
    for (region = newmem->regions;
         region < newmem->regions + mem.nregions;
         region++) {
        if (vhost_iotlb_add_range(newumem,
                      region->guest_phys_addr,
                      region->guest_phys_addr +
                      region->memory_size - 1, // Overflow here
                      region->userspace_addr,
                      VHOST_MAP_RW))
            goto err;
    }
```

**What’s the fix (high-level)?**
- Add explicit check: `if (region->guest_phys_addr + region->memory_size < region->guest_phys_addr) return -EFAULT;` before calling `vhost_iotlb_add_range`.

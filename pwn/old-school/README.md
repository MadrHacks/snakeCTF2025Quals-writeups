# old school [_snakeCTF 2025 Quals_]

**Category**: pwn
**Author**: c0mm4nd_

## Description

Tcache is overrated

*Please read the Dockerfile, especially the `GLIBC_TUNABLES` variable before attempting the challenge* 🙂

## Solution

This challenge is a heap exploitation problem targeting glibc version 2.42 (the latest at the time of writing). The main constraints are the absence of tcache, enforced by the tunables `glibc.malloc.tcache_count=0` and `glibc.malloc.tcache_max=0`, and a restriction on allocation sizes up to 0x68. As a result, every freed chunk is placed in the fastbins. A menu-driven interface is provided, allowing allocation, freeing, viewing, editing, and resizing of up to 32 chunks.

The vulnerability lies in the resize function: resizing an allocation to `0` frees the chunk and returns without updating the `allocated_chunk` and `allocated` fields. However, since the `requested_size` field is updated before the realloc call, editing the freed chunk is not directly possible. This creates the conditions for a double-free.

The exploitation is straightforward using the well-known *fastbin dup* technique, which involves freeing another chunk between the two frees:
- `alloc(0x68) # A`
- `alloc(0x68) # B`
- `resize(A, 0) # A is freed, but the allocated_chunk and allocated fields are not updated`
- `free(B) # B is freed`
- `free(A) # A is freed again`

### Leaking libc

The double-free primitive enables a use-after-free (UAF) condition, providing control over the fastbin freelist. However, the heap contains no useful targets for exploitation, necessitating a libc or binary leak to proceed.

The standard approach of freeing chunks into the unsorted bin (which contains libc pointers) is blocked by the size restrictions and unlimited fastbin capacity that keeps all freed allocations in fastbins.

Allocating over another chunk's header to modify its size is prevented by consistency checks during the free, edit, and resize operations.

The viable approach involves triggering `malloc_consolidate`, which happens when there is not enough space in the top chunk for a requested allocation but there's at least one chunk in the fastbins. By controlling the top chunk size, it becomes possible to force consolidation of fastbin chunks to satisfy the requested allocation size. The returned chunks have passed through the unsorted bin and thus contain libc pointers.

#### Bypassing size validation with IS_MMAPED

To write to a chunk, the challenge validates that the current chunk size matches the size saved at allocation time and that this size is greater than or equal to the requested write size.

The size verification relies on `malloc_usable_size`, which returns 0 for NULL pointers or calls the internal `musable` function:

```c
static size_t
musable (void *mem)
{
  mchunkptr p = mem2chunk (mem);

  if (chunk_is_mmapped (p))
    return chunksize (p) - CHUNK_HDR_SZ;
  else if (inuse (p))
    return memsize (p);

  return 0;
}
```

The `else if` branch checks the in-use bit stored in the next chunk's header, normally requiring careful alignment for faked chunks. This requirement can be bypassed by setting the `IS_MMAPED` bit in the chunk header, which skips the in-use check and directly returns `(size & ~0x7) - 16`.

### Enabling tcache

With libc addresses leaked, the next stage focuses on re-enabling tcache to simplify subsequent allocations. Tcache provides significant advantages as it performs no header validation checks, at least during allocation.

The tcache configuration is controlled by variables in the [`mp_` global struct](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source/malloc/malloc.c#L1933-L1936). Overwriting these variables involves constructing a chain of fake fastbin headers starting from the `__fpu_control` symbol in libc. This symbol is conveniently located after an interpretable chunk header with size `0x22` (which has the IS_MMAPED bit set). The chain is extended by writing fake chunk headers through writable libc symbols until the `mp_` struct is reached, where tcache parameters can be modified.

### Leaking the stack

With tcache enabled, allocating chunks near `__libc_argv` becomes straightforward without complex fastbin chaining and due to the lack of validation on the print function, it can be easily leaked.

### Controlling the allocations array

Leveraging the leaked stack address it becomes possible to allocate chunks that overlap with stack data, possibly targeting function return addresses. However, writing to stack-overlapping chunks requires valid headers.

A valid header can be constructed using the stored menu choice option. For example, choice 'e' (0x65 in hex) can be interpreted as a chunk of size 0x60. Since this value lacks the IS_MMAPED bit, `malloc_usable_size` checks the next chunk's PREV_INUSE bit, which corresponds to the `argc` value on the stack. With `argc` equal to 1 (program name as first argument), the chunk validates successfully with a usable size of 0x58.

This chunk contains the main function's frame, with both the allocated chunks array pointer and the return address. Direct return address overwriting is prevented by the stack canary, and leaking the array location is difficult due to its least significant byte always being zero.

### Hijacking the control flow

A possible solution involves overwriting the allocated chunks array pointer to gain control over future allocations. This control enables handling of unaligned allocations, customization of allocated_size values, and bypassing the need to pass through malloc for allocations, hence avoiding alignment constraints.

Finally, it becomes possible to use the most significant byte of a stack return address as a chunk's allocated size. This is possible when the most significant byte of this return address (relative to the binary) has the IS_MMAPED bit set (50% probability), ultimately enabling the overwrite of the `chunk_edit` function's return address and achieving code execution.
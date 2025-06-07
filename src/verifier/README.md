# Verifier

## TODO
1. 


## Undone
- Implementaion of function `check_mem_access`
  - reg.type == PTR_TO_STACK
- Type change
  - if map is read-only, track its contents as scalars
  - helper functions return (r[0].type)
- Concept of 'subprog'
  - only the first subprog's initial r[1]'s type is set as `PTR_TO_CTX` 

## Unrigorously implemented
- **Setting of flag `strict_alignment_` in class `State`**
  - In verifier.c, `env-> strict_alignment` is set like this:
    ```c++
    env->strict_alignment = !!(attr->prog_flags & BPF_F_STRICT_ALIGNMENT);
    if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
        env->strict_alignment = true;
    if (attr->prog_flags & BPF_F_ANY_ALIGNMENT)
        env->strict_alignment = false;
    ```
  - Due to the difficulty of calling `IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)`, now the flag `strict_alignment_` in class `State` is always set `true`.
- **Implementation of function `check_map_access_type`**
  - This function checks if map is readable or writable
  - Now directly returns 0

## Difference between verifier.c
- **Skip `check_map_access`**
  - This function checks if target map region is readable or writable
  - Our implementation: directly returns 0.
- **Skip `check_ctx_access`**
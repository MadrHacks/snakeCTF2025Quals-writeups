## Instruction Format

### Type A: register-register operations
```
[15-12] [11-8] [7-4] [3-0]
 OPCODE   RD    RA   RB
```

### Type b: memory Operations
```
[15-12] [11-8] [7-4] [3-0]
 OPCODE   RD    RA   IMM4
```

### Type C: register-immediate operations
```
[15-12] [11-8] [7-0]
 OPCODE   RD   IMM8
```

## Instruction Set

### Arithmetic & Logic (Type A)
- **0x0: ADD**  `RD = RA + RB`
- **0x1: SUB**  `RD = RA - RB`
- **0x2: AND**  `RD = RA & RB`
- **0x3: OR**   `RD = RA | RB`
- **0x4: XOR**  `RD = RA ^ RB`
- **0x5: SHL**  `RD = RA << (RB rem 16)` (logical shift)

### Memory Operations (Type B)
- **0x6: LDR**  `RD = MEMDATA[RA + sign_extend(IMM4)]` (load register from memdata)
- **0x7: STR**  `MEMDATA[RA + sign_extend(IMM4)] = RD` (store register to memdata)

### Immediate Operations (Type C)
- **0x8: LI**   `RD = sign_extend(IMM8)` (load immediate)
- **0x9: LIS**  `RD = IMM8 << 8` (load immediate shifted - upper 8 bits)
- **0xA: ADDI** `RD = RD + sign_extend(IMM8)` (add immediate to self)

### Branch Operations (Type C)
- **0xB: B**    `PC = RD + 2 * sign_extend(IMM8)` (unconditional jump to register+offset)
- **0xC: BL**   `R14 = PC + 2; PC = RD + 2 * sign_extend(IMM8)` (branch and link to register+offset)
- **0xD: BNZ**  `if (RD != 0) PC += 2 * sign_extend(IMM8)` (non-zero conditional branch)
- **0xE: BGT**  `if (RD > 0) PC += 2 * sign_extend(IMM8)` (signed greater than zero conditional branch)

### Syscall (Type C)
- **0xF: SYS**  `syscall IMM8` (system call)

#### Syscalls
- **0x1: sys_halt**  stop program
- **0x2: sys_putchar**  print character in r0
- **0x3: sys_getchar**  read character to r0

## Registers
- **R0-R13**: General purpose
- **R14**: Link register (LR) - return address storage
- **R15**: Program counter (PC)

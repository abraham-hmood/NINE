/* NINE built-in smoke test: freestanding x86-64 Linux program.
 * Uses only the instructions NINE's interpreter/JIT already covers:
 * mov, lea, xor, syscall and ret. No libc, no dynamic loader.
 */
typedef unsigned long u64;

static long sys_write(long fd, const void *buf, u64 n) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(1L), "D"(fd), "S"(buf), "d"(n)
                     : "rcx", "r11", "memory");
    return ret;
}

static __attribute__((noreturn)) void sys_exit(long code) {
    __asm__ volatile("syscall"
                     :
                     : "a"(60L), "D"(code)
                     : "rcx", "r11", "memory");
    __builtin_unreachable();
}

__attribute__((noreturn)) void _start(void) {
    static const char msg[] = "Hello, world from NINE!\n";
    sys_write(1, msg, sizeof(msg) - 1);
    sys_exit(0);
}

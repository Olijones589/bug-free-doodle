from os import system

syscalls = [
	"read", "write", "open", "close", "stat",
	"fstat", "lstat", "poll", "lseek", "mmap",
	"mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
	"rt_sigreturn", "ioctl", "pread", "pwrite", "readv",
	"writev", "access", "pipe", "select", "sched_yield",
	"mremap", "msync", "mincore", "madvise", "shmget",
	"shmat", "shmctl", "dup", "dup2", "pause",
	"nanosleep", "getitimer", "alarm", "setitimer", "getpid",
	"sendfile", "socket", "connect", "accept", "sendto",
	"recvfrom", "sendmsg", "recvmsg", "shutdown", "bind",
	"listen", "getsockname", "getpeername", "socketpair", "setsockopt",
	"getsockopt", "clone", "fork", "vfork", "execve",
	"exit", "wait4", "kill", "uname", "semget",
	"semop", "semctl", "shmdt", "msgget", "msgsnd",
	"msgrcv", "msgctl", "fcntl", "flock", "fsync",
	"fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
	"chdir", "fchdir", "rename", "mkdir", "rmdir",
	"creat", "link", "unlink", "symlink", "readlink",
	"chmod", "fchmod", "chown", "fchown", "lchown",
	"umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
	"times", "ptrace", "getuid", "syslog", "getgid",
	"setuid", "setgid", "geteuid", "getegid", "setpgid",
	"getppid", "getpgrp", "setsid", "setreuid", "setregid",
	"getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
	"getresgid", "getpgid", "setfsuid", "setfsgid", "getsid",
	"capget", "capset", "rt_sigpending", "rt_sigtimedwait", 
    "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", 
    "uselib",
	"personality", "ustat", "statfs", "fstatfs", "sysfs",
	"getpriority", "setpriority", "sched_setparam", "sched_getparam", 
    "sched_setscheduler",
	"sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
    "sched_rr_get_interval", "mlock",
	"munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
	"pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
	"setrlimit", "chroot", "sync", "acct", "settimeofday",
	"mount", "umount2", "swapon", "swapoff", "reboot",
	"sethostname", "setdomainname", "iopl", "ioperm", "create_module",
	"init_module", "delete_module", "get_kernel_syms", "query_module",
    "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", 
    "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
	"fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
	"llistxattr", "flistxattr", "removexattr", "lremovexattr", 
    "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", 
    "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", 
    "io_getevents", "io_submit", "io_cancel", "get_thread_area", 
    "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", 
    "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
	"semtimedop", "fadvise64", "timer_create", "timer_settime", 
    "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", 
    "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", 
    "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", 
    "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", 
    "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", 
    "kexec_load", "waitid", "add_key", "request_key", "keyctl", 
    "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch"
]

codes = {
	"stdout": 1,
	"stdin": 1,
	"stderr": 2
}

sections = {
        "text": []
} 

accum = 0

def se_add(section, text):
    if section not in sections:
        sections[section] = []
    sections[section].append(text)

def get_name(t="R"):
    global accum
    accum += 1
    return f"{t}{accum}"

se_add("text", "global _start")
se_add("text", "_start:")

def codify(text): 
    se_add("text", ("\t" * len(stack_shift)) + text)
def cmpr_op(operation, arguments):
    arguments = [str(a) for a in arguments]
    codify(f"{operation} {', '.join(arguments)}")

def cmpr_zero(reg):
    uses = "xor"
    if reg in FLOAT_REGISTERS: uses = "xorps"
    cmpr_op(uses, [reg, reg])

def cmpr_set(reg, v):
    if v == 0 or v == "0":
        cmpr_zero(reg)
        return

    cmpr_op("mov", [reg, v])

def cmpr_sub(reg, v):
    if not isinstance(v, str):
        if v < 0:
            cmpr_add(reg, -v)
            return

        if v == 1:
            cmpr_op("dec", [reg])
            return

        if v == 0: return
    cmpr_op("sub", [reg, v])

def cmpr_add(reg, v):
    if not isinstance(v, str):
        if v < 0:
            cmpr_sub(reg, -v)
            return

        if v == 1:
            cmpr_op("inc", [reg])
            return

        if v == 0: return
    cmpr_op("add", [reg, v])

def cmpr_cmp(reg, v): cmpr_op("cmp", [reg, v])
def cmpr_jmp(v): cmpr_op("jmp", [v])

CMP_INEQUALITIES = {
        "==": "je", "!=": "jne",
        ">": "jg", "<": "jl",
        ">=": "jge", "<=": "jle"
}

CMP_INVERSE = {
        "je": "jne", "jne": "je",
        "jg": "jle", "jl": "jge",
        "jle": "jg", "jge": "jl"
}

def cmpr_cmpjmp(reg, t, v, to, invert=False):
    if t in CMP_INEQUALITIES: t = CMP_INEQUALITIES[t]
    if invert and t not in CMP_INVERSE:
        quit(f"Unknown inversion for: {t}")

    if invert: t = CMP_INVERSE[t]

    cmpr_cmp(reg, v)
    if len(t) > 0 and t[0] == "j":
            
        cmpr_op(t, [to])
    else:
        quit("Invalid jmp command or jmp command alias!")

scope_stack = []
# not user space
def cmpr_scope(label, scopetype=None):
    stack_shift.append(0)
    scope_stack.append((label, scopetype))

# do not call this (not user-space!!)
def cmpr_endscope(scopetype=None):
    if stack_shift.pop() != 0:
        quit("End-of-scope stack shift is nonzero at scope exit")

    label = scope_stack.pop()
    codify(f"; end of {label}")
    if label[1] != scopetype:
        quit(f"Expected scopetype {scopetype}, got {label}")
    return label

def cmpr_if(reg, t, v):
    label = get_name("ENDIF")
    
    cmpr_cmpjmp(reg, t, v, label, invert=True)
    cmpr_scope(label, scopetype="if")
    return label

def cmpr_endif():
    label = cmpr_endscope(scopetype="if")
    codify(label[0] + ":")

def cmpr_while(reg, t, v):
    label = get_name("WHILE")

    codify(label + "START:")
    cmpr_cmpjmp(reg, t, v, label+"END", invert=True)
    cmpr_scope(label, scopetype="while")

def cmpr_endwhile():
    label = cmpr_endscope(scopetype="while")
    cmpr_jmp(label[0] + "START")
    codify(label[0] + "END:")

# calls endif, endwhile, etc.
def cmpr_end():
    label = scope_stack[-1]
    globals()[f"cmpr_end{label[1]}"]()

def cmpr_restart(): cmpr_jmp("_start")

# label = cmpr_if("rax", "==", 0, "why_so_quiet")
# cmpr_endif(label)

CALLING_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
FLOAT_REGISTERS = [f"xmm{i}" for i in range(0, 16)]
REGISTERS = CALLING_REGISTERS + FLOAT_REGISTERS

def cmpr_calling(args):
    floats = 0
    normal = 0
    for i in range(0, len(args)):
        if isinstance(args[i], float): 
            reg = FLOAT_REGISTERS[floats]
            floats += 1
        else: 
            reg = CALLING_REGISTERS[normal]
            normal += 1

        cmpr_set(reg, args[i])


def cmpr_syscall(code, args):
    if code in syscalls: code = syscalls.index(code)

    codify(f"; {code} {args}")
    cmpr_set("rax", code)
    cmpr_calling(args)
    codify("syscall")
    return "rax"

def cmpr_constr(text):
    name = get_name(t="STR")

    print_d = ""
    for i in range(0, len(text)):
        print_d += str(ord(text[i])) + ", "
    print_d = print_d[:-2]

    se_add("rodata", f"\t{name} db {print_d}")
    return name

def cmpr_conprint(text):
    string = cmpr_constr(text)
    cmpr_syscall(syscalls.index("write"), [codes["stdout"], string, len(text)])

stack_shift = [0]
def cmpr_stack_bytes(allocs):
    global stack_shift
    stack_shift[-1] += allocs
    cmpr_sub("rsp", allocs)

# Shifts by words to allow for a C ffi (ex. libc, although not supported
# as of now because the entry point is locked at _start).
# Doesn't need to be this way, you can use cmpr_stack_bytes if needed for
# other alignments.
def cmpr_stack(words): cmpr_stack_bytes(words * 16)

on_stack = []
def cmpr_op_push(what): 
    on_stack.append(what)
    cmpr_op("push", [what])

# what is an optional kwarg to assert the register
#   you pop from
def cmpr_op_pop(what=None): 
    pop_from = on_stack.pop()
    cmpr_op("pop", [pop_from])

    if what == None: return
    if pop_from != what:
        quit(f"Tried popping a {what}, got a {pop_from}")

def cmpr_push(what):
    if what in REGISTERS:
        cmpr_op_push(what)
        return

    quit("Non-register push unsupported as of now.")

def cmpr_pop(what):
    if what in REGISTERS:
        cmpr_op_pop(what)
        return
   
    quit("Non-register pop unsupported as of now.")

def cmpr_exit(code=0):
    cmpr_syscall("exit", [code])

def cmpr_max(reg): cmpr_set(reg, -1)

TOKEN_EMPTY = 0
TOKEN_ABSTRACT = 1
TOKEN_SYMBOL = 2
TOKEN_COMMENT = 3

def cmpr_tokenize(src):
    tokens = []
    
    # this new model works differently. It's an array of strings upon a token's
    # finishing a new token is appended. because we always concatinate 
    # to the last token, this is a soft send
    for char in src:
        if char == "\n" or char == ";":
            tokens.append([ TOKEN_ABSTRACT, "END_INSTRUCTION" ])
            tokens.append([ TOKEN_EMPTY, "" ])
            continue

def cmpr_compile_src(src):
    tokens = cmpr_tokenize(src)
    # cmpr_set("rbp", "rsp")
    # cmpr_conprint("What's your name? ")
    #
    # cmpr_set("r14", cmpr_syscall("read", [codes["stdin"], "rsp", 64]))
    #
    # cmpr_sub("r14", 1)
    #
    # cmpr_if("r14", "==", 0)
    # cmpr_conprint("I find it hard to believe your name is ''.\n")
    # cmpr_set("r14", 3)
    # cmpr_set("[rsp]", "'y'")
    # cmpr_set("[rsp + 1]", "'o'")
    # cmpr_set("[rsp + 2]", "'u'")
    # cmpr_end()
    #
    # cmpr_conprint("Hi, ")
    # cmpr_syscall("write", [codes["stdout"], "rsp", "r14"])
    #
    # cmpr_if("r14", "==", 64)
    # cmpr_conprint("[truncated]")
    # cmpr_end()
    #
    # cmpr_conprint("!\n")
    # cmpr_set("rsp", "rbp")
    # cmpr_exit(0)

    return

def cmpr_compile(filename):
    file = open(filename, "r")
    cmpr_compile_src(file.read())
    file.close()

res = ""
for section in sections:
    res += "section ." + section + "\n"
    res += "\n".join(sections[section]) + "\n"

file = open("tmp.nasm", "w")
file.write(res)
file.close()
system("nasm -felf64 tmp.nasm -o tmp.o && ld tmp.o")

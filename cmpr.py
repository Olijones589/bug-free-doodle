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
def gen_op(operation, arguments):
    arguments = [str(a) for a in arguments]
    codify(f"{operation} {', '.join(arguments)}")

def gen_zero(reg):
    uses = "xor"
    if reg in FLOAT_REGISTERS: uses = "xorps"
    gen_op(uses, [reg, reg])

def gen_set(reg, v):
    if v == 0 or v == "0":
        gen_zero(reg)
        return

    gen_op("mov", [reg, v])

def gen_sub(reg, v):
    if not isinstance(v, str):
        if v < 0:
            gen_add(reg, -v)
            return

        if v == 1:
            gen_op("dec", [reg])
            return

        if v == 0: return
    gen_op("sub", [reg, v])

def gen_add(reg, v):
    if not isinstance(v, str):
        if v < 0:
            gen_sub(reg, -v)
            return

        if v == 1:
            gen_op("inc", [reg])
            return

        if v == 0: return
    gen_op("add", [reg, v])

def gen_cmp(reg, v): cmpr_op("cmp", [reg, v])
def gen_jmp(v): cmpr_op("jmp", [v])

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

def gen_cmpjmp(reg, t, v, to, invert=False):
    if t in CMP_INEQUALITIES: t = CMP_INEQUALITIES[t]
    if invert and t not in CMP_INVERSE:
        quit(f"Unknown inversion for: {t}")

    if invert: t = CMP_INVERSE[t]

    gen_cmp(reg, v)
    if len(t) > 0 and t[0] == "j":
            
        gen_op(t, [to])
    else:
        quit("Invalid jmp command or jmp command alias!")

scope_stack = []
# not user space
def gen_scope(label, scopetype=None):
    stack_shift.append(0)
    scope_stack.append((label, scopetype))

# do not call this (not user-space!!)
def gen_endscope(scopetype=None):
    if stack_shift.pop() != 0:
        quit("End-of-scope stack shift is nonzero at scope exit")

    label = scope_stack.pop()
    codify(f"; end of {label}")
    if label[1] != scopetype:
        quit(f"Expected scopetype {scopetype}, got {label}")
    return label

def gen_if(reg, t, v):
    label = get_name("ENDIF")
    
    gen_cmpjmp(reg, t, v, label, invert=True)
    gen_scope(label, scopetype="if")
    return label

def gen_endif():
    label = gen_endscope(scopetype="if")
    codify(label[0] + ":")

def gen_while(reg, t, v):
    label = get_name("WHILE")

    codify(label + "START:")
    gen_cmpjmp(reg, t, v, label+"END", invert=True)
    gen_scope(label, scopetype="while")

def gen_endwhile():
    label = gen_endscope(scopetype="while")
    gen_jmp(label[0] + "START")
    codify(label[0] + "END:")

# calls endif, endwhile, etc.
def gen_end():
    label = scope_stack[-1]
    globals()[f"gen_end{label[1]}"]()

def gen_restart(): cmpr_jmp("_start")

# label = gen_if("rax", "==", 0, "why_so_quiet")
# gen_endif(label)

CALLING_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
FLOAT_REGISTERS = [f"xmm{i}" for i in range(0, 16)]
REGISTERS = CALLING_REGISTERS + FLOAT_REGISTERS

def gen_calling(args):
    floats = 0
    normal = 0
    for i in range(0, len(args)):
        if isinstance(args[i], float): 
            reg = FLOAT_REGISTERS[floats]
            floats += 1
        else: 
            reg = CALLING_REGISTERS[normal]
            normal += 1

        gen_set(reg, args[i])


def gen_syscall(code, args):
    if code in syscalls: code = syscalls.index(code)

    codify(f"; {code} {args}")
    gen_set("rax", code)
    gen_calling(args)
    codify("syscall")
    return "rax"

def gen_constr(text):
    name = get_name(t="STR")

    print_d = ""
    for i in range(0, len(text)):
        print_d += str(ord(text[i])) + ", "
    print_d = print_d[:-2]

    se_add("rodata", f"\t{name} db {print_d}")
    return name

def gen_conprint(text):
    string = gen_constr(text)
    gen_syscall(syscalls.index("write"), [codes["stdout"], string, len(text)])

stack_shift = [0]
def gen_stack_bytes(allocs):
    global stack_shift
    stack_shift[-1] += allocs
    gen_sub("rsp", allocs)

# Shifts by words to allow for a C ffi (ex. libc, although not supported
# as of now because the entry point is locked at _start).
# Doesn't need to be this way, you can use gen_stack_bytes if needed for
# other alignments.
def gen_stack(words): cmpr_stack_bytes(words * 16)

on_stack = []
def gen_op_push(what): 
    on_stack.append(what)
    gen_op("push", [what])

# what is an optional kwarg to assert the register
#   you pop from
def gen_op_pop(what=None): 
    pop_from = on_stack.pop()
    gen_op("pop", [pop_from])

    if what == None: return
    if pop_from != what:
        quit(f"Tried popping a {what}, got a {pop_from}")

def gen_push(what):
    if what in REGISTERS:
        gen_op_push(what)
        return

    quit("Non-register push unsupported as of now.")

def gen_pop(what):
    if what in REGISTERS:
        gen_op_pop(what)
        return
   
    quit("Non-register pop unsupported as of now.")

def gen_exit(code=0):
    gen_syscall("exit", [code])

def gen_max(reg): cmpr_set(reg, -1)

KEYWORDS = [
	"if", "else", "do",
	"then", "while", "for",
	"function", "break", "continue",
	"return", "local", "and",
    "elseif", "end", "false", "true",
    "in", "local", "nil",
    "not", "or", "repeat"
]

TOKEN = {
	"UNDEFINED": 0,
	"ABSTRACT": 1,
	"SYMBOL": 2,
	"COMMENT": 3,
	"STRING": 4,
	"INTEGER": 5,
	"FLOAT": 6,
    "KEYWORD": 7
}

def is_letter(x):
    x = x.lower()
    return ord(x) >= ord('a') and ord(x) <= ord('z')

def is_number(x):
    return ord(x) >= ord('0') and ord(x) <= ord('9')

def char_type(x):
    if is_letter(x):
        return 0
    elif is_number(x):
        return 1
    else:
        return 2

def gen_tokenize(src):
    tokens = []
    in_quote = False
    quote_delim = None
    last_type = None
    this_type = None

    for i, char in enumerate(src):
        this_type = char_type(char)
        if last_type == None:
            last_type = this_type

        if i > 0: last_char = src[i - 1]
        if char in (['"', "'"] if not in_quote else [quote_delim]) and last_char != "\\":
            in_quote = not in_quote
            tokens.append([ TOKEN["STRING"] if in_quote else TOKEN["UNDEFINED"], "" ])
            quote_delim = char if in_quote else None
            continue

        if in_quote: 
            tokens[-1][1] += char
            continue

        if char == "\n" or char == ";":
            tokens.append([ TOKEN["ABSTRACT"], "END_INSTRUCTION" ])
            tokens.append([ TOKEN["UNDEFINED"], "" ])
            continue

        if len(tokens) == 0: tokens.append([ TOKEN["UNDEFINED"], "" ])
    
        if last_type != this_type:
            tokens.append([ TOKEN["UNDEFINED"], "" ])

        tokens[-1][1] += char

    # second pass to turn SYMBOLs into KEYWORDs
    for i, token in enumerate(tokens):
        if token[1].strip() == "":
            tokens[i] = None
        elif token[1] in KEYWORDS:
            token[0] = TOKEN["KEYWORD"]
            tokens.append([ TOKEN["UNDEFINED"], "" ])
        elif token[0] == TOKEN["UNDEFINED"]:
            token[0] = TOKEN["SYMBOL"]
            token[1] = token[1].strip()

    if tokens[-1] != None and tokens[-1][0] == TOKEN["UNDEFINED"]:
        tokens.pop()
    
    filtered_tokens = []
    for token in tokens:
        if token == None: continue
        filtered_tokens.append(token)

    return filtered_tokens

def gen_compile_src(src):
    global sections

    tokens = gen_tokenize(src)
    
    print(tokens)

    quit("TODO: parse tokens")

    sections = {}
    se_add("text", "global _start")
    se_add("text", "_start:")
    gen_set("rbp", "rsp")
    # gen_conprint("What's your name? ")
    #
    # gen_set("r14", cmpr_syscall("read", [codes["stdin"], "rsp", 64]))
    #
    # gen_sub("r14", 1)
    #
    # gen_if("r14", "==", 0)
    # gen_conprint("I find it hard to believe your name is ''.\n")
    # gen_set("r14", 3)
    # gen_set("[rsp]", "'y'")
    # gen_set("[rsp + 1]", "'o'")
    # gen_set("[rsp + 2]", "'u'")
    # gen_end()
    #
    # gen_conprint("Hi, ")
    # gen_syscall("write", [codes["stdout"], "rsp", "r14"])
    #
    # gen_if("r14", "==", 64)
    # gen_conprint("[truncated]")
    # gen_end()
    #
    # gen_conprint("!\n")
    gen_set("rsp", "rbp")
    gen_exit(0)

    res = ""
    for section in sections:
        res += "section ." + section + "\n"
        res += "\n".join(sections[section]) + "\n"
    
    sections = {}

    return res

def gen_compile(filename):
    file = open(filename, "r")
    res = gen_compile_src(file.read())
    file.close()
    return res

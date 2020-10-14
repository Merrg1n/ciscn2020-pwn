//gcc main.c -std=c99 -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-all -z noexecstack -pie -fPIE -z now -s -o pwn
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

struct func
{
    uint32_t length;
    uint32_t start_addr;
    uint8_t *code;
    uint32_t random_offset;
};
enum op_ptr_type
{
    PTR_BYTE,
    PTR_WORD,
    PTR_DWORD,
    PTR_QWORD,
};
enum op_branch_cond
{
    COND_NONE,
    COND_EQ,
    COND_NEQ,
    COND_GT,
    COND_LT,
    COND_GE,
    COND_LE
};
enum reg_flag
{
    FLAG_NONE,
    FLAG_EQ,
    FLAG_GT,
    FLAG_LT
};
enum addr_type
{
    ADDR_STACK = 0x100000000000000UL,
    ADDR_FUNC = 0x200000000000000UL
};

uint8_t stack[0x1000];
struct func func_list[16] = {0};
uint64_t regs[16];
enum reg_flag reg_flag = FLAG_NONE;
uint32_t func_count = 0;

#define get_hi4(b) (b >> 4)
#define get_lo4(b) (b & 0b1111)
#define pack(hi, lo) (hi << 4 | lo)
#define to_func_addr(id) (((uint64_t)id << 60 | ADDR_FUNC) + (func_list + id)->start_addr + (func_list + id)->random_offset)

void *parse_addr(uint64_t addr)
{
    if (addr & ADDR_STACK)
    {
        uint64_t offset = addr ^ ADDR_STACK;
        if (offset < 0 || offset > 1000)
            return NULL;
        else
            return stack + offset;
    }
    if (addr & ADDR_FUNC)
    {
        uint64_t offset = addr & 0xffffffff;
        uint64_t funcid = addr >> 60;
        struct func *p_func = func_list + funcid;
        if (offset < p_func->random_offset)
            return NULL;
        else
            return p_func->code + offset - p_func->random_offset;
    }
    return NULL;
}
void push(uint8_t regid)
{
    void *ptr = parse_addr(regs[14]);
    if (ptr == NULL)
    {
        printf("Bad SP.");
        exit(-1);
    }
    *(uint64_t *)ptr = regs[regid];
    regs[14] += 8;
}
void pop(uint8_t regid)
{
    regs[14] -= 8;
    void *ptr = parse_addr(regs[14]);
    if (ptr == NULL)
    {
        printf("Bad SP.");
        exit(-1);
    }
    regs[regid] = *(uint64_t *)ptr;
}

bool op_loadi(uint8_t *pc)
{
    regs[get_lo4(*pc)] = *(uint64_t *)(pc + 1);
    regs[15] += 9;
    return true;
}

bool op_load(uint8_t *pc)
{
    uint8_t first = get_hi4(*(pc + 1)), second = get_lo4(*(pc + 1));
    int64_t offset = *(int32_t *)(pc + 2); //lift up, sign extended
    if (first == 15)
    {
        printf("Cannot control pc :( \n");
        return false;
    }
    void *ptr = parse_addr(regs[second] + offset);
    if (ptr == NULL)
    {
        printf("Bad Address.");
        return false;
    }
    switch (get_lo4(*pc))
    {
    case PTR_BYTE:
        regs[first] = *(uint8_t *)ptr;
        break;
    case PTR_WORD:
        regs[first] = *(uint16_t *)ptr;
        break;
    case PTR_DWORD:
        regs[first] = *(uint32_t *)ptr;
        break;
    case PTR_QWORD:
        regs[first] = *(uint64_t *)ptr;
        break;
    default:
        printf("Unknown ptr type.\n");
        return false;
    }
    regs[15] += 6;
    return true;
}
bool op_save(uint8_t *pc)
{
    uint8_t first = get_hi4(*(pc + 1)), second = get_lo4(*(pc + 1));
    int64_t offset = *(int32_t *)(pc + 2); //lift up, sign extended
    void *ptr = parse_addr(regs[second] + offset);
    if (ptr == NULL)
    {
        printf("Bad Address.");
        return false;
    }
    switch (get_lo4(*pc))
    {
    case PTR_BYTE:
        *(uint8_t *)ptr = regs[first];
        break;
    case PTR_WORD:
        *(uint16_t *)ptr = regs[first];
        break;
    case PTR_DWORD:
        *(uint32_t *)ptr = regs[first];
        break;
    case PTR_QWORD:
        *(uint64_t *)ptr = regs[first];
        break;
    default:
        printf("Unknown ptr type.\n");
        return false;
    }
    regs[15] += 6;
    return true;
}

bool op_mov(uint8_t *pc)
{
    uint8_t first = get_lo4(*pc), second = get_hi4(*(pc + 1));
    if (first == 15)
    {
        printf("Cannot control pc :( \n");
        return false;
    }
    regs[first] = regs[second];
    regs[15] += 2;
    return true;
}
bool op_add(uint8_t *pc)
{
    regs[get_lo4(*pc)] = regs[get_hi4(*(pc + 1))] + regs[get_lo4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_sub(uint8_t *pc)
{
    regs[get_lo4(*pc)] = regs[get_hi4(*(pc + 1))] - regs[get_lo4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_and(uint8_t *pc)
{
    regs[get_lo4(*pc)] = regs[get_hi4(*(pc + 1))] & regs[get_lo4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_or(uint8_t *pc)
{
    regs[get_lo4(*pc)] = regs[get_hi4(*(pc + 1))] | regs[get_lo4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_xor(uint8_t *pc)
{
    regs[get_lo4(*pc)] = regs[get_hi4(*(pc + 1))] ^ regs[get_lo4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_not(uint8_t *pc)
{
    regs[get_lo4(*pc)] = ~regs[get_hi4(*(pc + 1))];
    regs[15] += 2;
    return true;
}
bool op_push(uint8_t *pc)
{
    push(get_lo4(*pc));
    regs[15] += 1;
    return true;
}
bool op_pop(uint8_t *pc)
{
    pop(get_lo4(*pc));
    regs[15] += 1;
    return true;
}
bool op_call(uint8_t *pc)
{
    uint8_t func_id = get_lo4(*pc);
    if (func_list[func_id].length == 0)
    {
        printf("Invaild func id on call.\n");
        return false;
    }
    regs[15] += 1;
    //push pc
    push(15);
    //push old bp
    push(13);
    //mov sp to bp
    regs[13] = regs[14];
    //jump to func
    regs[15] = to_func_addr(func_id);
    return true;
}
bool op_ret(uint8_t *pc)
{
    if (regs[13] != ADDR_STACK)
    {
        //mov bp to sp
        regs[14] = regs[13];
        //pop old bp
        pop(13);
        //pop pc
        pop(15);
        //push result
        push(get_lo4(*pc));
        return true;
    }
    else
    {
        void *ptr = parse_addr(regs[get_lo4(*pc)]);
        if (ptr == NULL)
        {
            printf("no result.");
            return;
        }
        //print result
        for (uint8_t *p = (uint8_t *)ptr; *p; p++)
            putchar(*p);
        putchar('\n');
        return false;
    }
}
bool op_cmp(uint8_t *pc)
{
    uint64_t first = regs[get_lo4(*pc)], second = regs[get_hi4(*(pc + 1))];
    if (first == second)
        reg_flag = FLAG_EQ;
    else if (first > second)
        reg_flag = FLAG_GT;
    else
        reg_flag = FLAG_LT;
    regs[15] += 2;
    return true;
}
bool op_branch(uint8_t *pc)
{
    bool should_branch = false;
    switch (get_lo4(*pc))
    {
    case COND_NONE:
        should_branch = true;
        break;
    case COND_EQ:
        should_branch = reg_flag == FLAG_EQ;
        break;
    case COND_NEQ:
        should_branch = reg_flag != FLAG_EQ;
        break;
    case COND_GT:
        should_branch = reg_flag == FLAG_GT;
        break;
    case COND_LT:
        should_branch = reg_flag == FLAG_LT;
        break;
    case COND_GE:
        should_branch = reg_flag == FLAG_EQ || reg_flag == FLAG_GT;
        break;
    case COND_LE:
        should_branch = reg_flag == FLAG_EQ || reg_flag == FLAG_LT;
        break;
    default:
        printf("Unknown branch condition.\n");
        return false;
    }
    int64_t offset = *(int32_t *)(pc + 1); //lift up, sign extended
    if (should_branch)
        regs[15] = regs[15] + offset;
    else
        regs[15] += 5;
    return true;
}
bool (*op_funcs[])(uint8_t *) = {op_loadi,
                                 op_load,
                                 op_save,
                                 op_mov,
                                 op_add,
                                 op_sub,
                                 op_and,
                                 op_or,
                                 op_xor,
                                 op_not,
                                 op_push,
                                 op_pop,
                                 op_call,
                                 op_ret,
                                 op_cmp,
                                 op_branch};
void run_func(uint32_t func_id)
{
    memset(stack, 0, sizeof(stack));
    memset(regs, 0, sizeof(regs));
    regs[13] = ADDR_STACK;            //bp
    regs[14] = ADDR_STACK;            //sp
    regs[15] = to_func_addr(func_id); //pc
    reg_flag = FLAG_NONE;
    while (1)
    {
        uint8_t *pc = (uint8_t *)parse_addr(regs[15]);
        bool should_continue = op_funcs[get_hi4(*pc)](pc);
        if (!should_continue)
            break;
    }
}

void menu()
{
    printf("1. Create function\n");
    printf("2. Remove function\n");
    printf("3. Run function\n");
    printf("0. Exit\n");
}
void menu_create()
{
    if (func_count >= 16)
    {
        printf("Fail to create function.\n");
        return;
    }
    uint32_t length, start_addr;

    printf("Input code length:\n");
    scanf("%u", &length);

    uint8_t *buf = (uint8_t *)malloc(length + 1);
    if (buf == NULL)
    {
        printf("Fail to allocate space.\n");
        return;
    }
    printf("Input your code:\n");
    fread(buf, 1, length, stdin);

    printf("Input start address:\n");
    scanf("%u", &start_addr);
    if (start_addr >= length)
    {
        printf("Invalid start address.\n");
        return;
    }

    printf("Your function ID:%d\n", func_count);
    struct func *p_func = func_list + func_count;
    p_func->code = buf;
    p_func->length = length;
    p_func->start_addr = start_addr;
    p_func->random_offset = rand() % 114;
    func_count++;
}
void menu_remove()
{
    uint32_t func_id;

    printf("Input function ID:\n");
    scanf("%u", &func_id);
    if (func_id >= 16 || func_list[func_id].length == 0)
    {
        printf("Invalid function ID.\n");
        return;
    }
    free(func_list[func_id].code);
    func_list[func_id].length = 0;
}
void menu_run()
{
    uint32_t func_id;

    printf("Input function ID:\n");
    scanf("%u", &func_id);
    if (func_id >= 16 || func_list[func_id].length == 0)
    {
        printf("Invalid function ID.\n");
        return;
    }
    run_func(func_id);
}
void menu_exit()
{
    exit(EXIT_SUCCESS);
}

void (*menu_list[])() = {menu_exit, menu_create, menu_remove, menu_run};
int main()
{
    srand(time(0));
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    while (1)
    {
        uint32_t choice = 0;
        menu();
        scanf("%u", &choice);
        if (choice > 3)
            printf("Invalid choice.\n");
        else
            menu_list[choice]();
    }
    return 0;
}

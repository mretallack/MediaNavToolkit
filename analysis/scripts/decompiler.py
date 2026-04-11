#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from ghidra.app.decompiler import DecompInterface
import __main__ as ghidra_app


class Decompiler:
    def __init__(self, program=None, timeout=None):
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._timeout = timeout

    def decompile_func(self, func):
        dec_status = self._decompiler.decompileFunction(func, 0, self._timeout)
        if dec_status and dec_status.decompileCompleted():
            dec_ret = dec_status.getDecompiledFunction()
            if dec_ret:
                return dec_ret.getC()

    def decompile(self):
        pseudo_c = ''
        funcs = ghidra_app.currentProgram.getListing().getFunctions(True)
        for func in funcs:
            dec_func = self.decompile_func(func)
            if dec_func:
                pseudo_c += dec_func
        return pseudo_c


def run():
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        return
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}_decompiled.c'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]

    decompiler = Decompiler()
    pseudo_c = decompiler.decompile()

    with open(output, 'w') as fw:
        fw.write(pseudo_c)
    print('[*] success. save to -> {}'.format(output))


if __name__ == '__main__':
    run()

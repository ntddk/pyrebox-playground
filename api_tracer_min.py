#!/usr/bin/env python
#coding: utf-8

from __future__ import print_function
import sys
import api
from utils import get_addr_space
from api import CallbackManager
from api import BP
import volatility.win32.modules as modules

cm = None
pyrebox_print = None

target_procname = "malware"
target_apiname = ["NtCreateFile", "NtDeleteFile"]

def new_proc(pid,pgd,name):
    global pyrebox_print
    global cm
    global target_procname
    global target_apiname

    if target_procname != "" and target_procname.lower() in name.lower():
        pyrebox_print("Target process detected! pid: %x, pgd: %x, name: %s" % (pid,pgd,name))
        addr_space = get_addr_space(pgd)
        modlist = list(modules.lsmod(addr_space))

        for mod in modlist:
            for ordinal, func_addr, func_name in mod.exports():
                if func_addr != None:
                    name = func_name or ordinal or ""

                    if filter(lambda x: name.lower() in x.lower(), target_apiname):
                        addr = mod.DllBase + func_addr
                        bp = BP(addr, pgd)
                        bp.enable()
                        pyrebox_print("Breakpoint set! addr: %x name: %s" % (addr, name))
    else:
        pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid,pgd,name))

def initialize_callbacks(module_hdl,printer):
    global cm
    global pyrebox_print

    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl)

    new_proc_cb = cm.add_callback(CallbackManager.CREATEPROC_CB,new_proc)

    pyrebox_print("[*]    Initialized callbacks")

def clean():
    global cm

    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))


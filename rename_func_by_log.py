import os

from ida_hexrays import (
    init_hexrays_plugin,
    decompile_func,
    hexrays_failure_t,
    MERR_FUNCSIZE,
    ctree_visitor_t,
    CV_FAST,
    cexpr_t,
    cot_call,
    cot_obj,
    get_ctype_name,
    DECOMP_NO_CACHE,
)
from ida_kernwin import (
    warning,
    get_screen_ea,
    Choose,
    info,
    ask_yn,
    ASKBTN_NO,
    ASKBTN_CANCEL,
)
from ida_funcs import get_func, func_t
from ida_typeinf import tinfo_t, func_type_data_t, funcarg_t
from ida_idaapi import BADADDR
from ida_bytes import (
    has_user_name,
    get_flags,
    is_strlit,
    get_strlit_contents,
    get_max_strlit_length,
    ALOPT_IGNHEADS,
)
from ida_nalt import STRTYPE_C
from idautils import CodeRefsTo
from ida_name import SN_CHECK, set_name, SN_FORCE

DEBUG = 0


def p(msg):
    print(f"{os.path.basename(__file__)}: {msg}")


def w(msg):
    print(f"{os.path.basename(__file__)}: {msg}")
    warning(msg)


def i(msg):
    print(f"{os.path.basename(__file__)}: {msg}")
    info(msg)


class CallVisitor(ctree_visitor_t):
    def __init__(self, call_address, arg_num):
        super().__init__(CV_FAST)
        self.call_address = call_address
        self.arg_num = arg_num

    def visit_expr(self, expr: cexpr_t):
        if expr.op != cot_call:
            return 0
        if expr.ea != self.call_address:
            return 0
        argument = expr.a[self.arg_num]
        if argument.op != cot_obj:
            # TODO: if cot_var, then should be data-flow analysis
            if argument.ea == BADADDR:
                msg = f"Not object (bad address): {self.call_address:#x} ({get_ctype_name(argument.op)})"
            else:
                msg = f"Not object: {argument.ea:#x} ({get_ctype_name(argument.op)})"
            p(msg)
            return 1
        obj_address = argument.obj_ea
        flags = get_flags(obj_address)
        if not is_strlit(flags):
            p(f"Not string argument: {argument.ea:#x} ({obj_address:#x})")
            return 1
        str_len = get_max_strlit_length(obj_address, STRTYPE_C, ALOPT_IGNHEADS)
        name = get_strlit_contents(obj_address, str_len, STRTYPE_C).decode()
        # don't check, checked before
        caller_function: func_t = get_func(self.call_address)
        caller_address = caller_function.start_ea
        if DEBUG:
            p(f"{caller_function.name} ({caller_address:#x}) -> {name}")
        if not set_name(caller_address, name, flags=SN_CHECK | SN_FORCE):
            p(f'Can\'t rename function ({caller_address:#x}) to "{name}"')
            return 1
        return 1


class ArgChooser(Choose):
    def __init__(self, args: func_type_data_t):
        super().__init__(
            "Arguments",
            [
                ["Type", 10],
                ["Name", 10],
            ],
        )
        self.args = args

    def OnGetSize(self):
        return self.args.size()

    def OnGetLine(self, n):
        arg: funcarg_t = self.args.at(n)
        return [arg.type.dstr(), arg.name]


def main():
    print("Start script {}".format(__file__))
    if not init_hexrays_plugin():
        w("Decompiler not initilized")
        return

    current_address = get_screen_ea()
    function: func_t = get_func(current_address)
    if function is None:
        w("Please position the cursor within a function")
        return
    hr_failure = hexrays_failure_t()
    cfunction = decompile_func(function, hr_failure)
    if cfunction is None:
        w(f"Decompilation failed at {function.start_ea:#x}: {hr_failure.desc()}")
        return
    signature = tinfo_t()
    if not cfunction.get_func_type(signature):
        w("Can't get signature of the function")
        return

    func_details = func_type_data_t()
    if not signature.get_func_details(func_details):
        w("Can't get details about function's signature")
        return
    arg_chooser = ArgChooser(func_details)
    arg_num = arg_chooser.Show(modal=True)
    if arg_num == Choose.NO_SELECTION:
        i("None of the arguments were selected")
        return

    is_use_cache = ask_yn(ASKBTN_NO, "Use the cache during decompilation?")
    if is_use_cache == ASKBTN_CANCEL:
        return
    visited_functions = []
    for current_xref in CodeRefsTo(function.start_ea, 1):
        if current_xref == BADADDR:
            break
        caller_function: func_t = get_func(current_xref)
        if caller_function is None:
            w(f"Callee address ({current_xref:#x}) is not function")
            continue
        call_address = caller_function.start_ea
        if call_address in visited_functions:
            continue
        if DEBUG:
            p(f"Visit {caller_function.name} ({call_address:#x})")
        visited_functions.append(call_address)
        flags = get_flags(call_address)
        if has_user_name(flags):
            if DEBUG:
                p(f"Already has name: {caller_function.get_name()} ({call_address:#x})")
            continue
        caller_cfunction = decompile_func(
            caller_function, hr_failure, 0 if is_use_cache else DECOMP_NO_CACHE
        )
        if caller_cfunction is None:
            if hr_failure.code == MERR_FUNCSIZE:
                p(f"Decompilation failed at {current_xref:#x}: {hr_failure.desc()}")
            else:
                w(f"Decompilation failed at {current_xref:#x}: {hr_failure.desc()}")
            continue
        visitor = CallVisitor(current_xref, arg_num)
        visitor.apply_to(caller_cfunction.body, None)


if __name__ == "__main__":
    main()

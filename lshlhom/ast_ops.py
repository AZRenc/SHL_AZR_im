import ast
import random
import hashlib
from typing import Dict, List, Set

from .sm4 import encrypt_cbc

_SHL_DUNDER = {
    '__init__', '__new__', '__repr__', '__str__', '__len__', '__enter__',
    '__exit__', '__aenter__', '__aexit__', '__call__', '__iter__',
    '__next__', '__getattr__', '__setattr__', '__delattr__', '__get__',
    '__set__', '__delete__', '__getattribute__', '__name__', '__doc__',
    '__module__', '__qualname__', '__class__', '__dict__', '__file__',
    '__spec__', '__loader__', '__package__', '__builtins__', '__debug__',
    '__path__', '__all__', '__version__', '__author__', '__annotations__',
    '__slots__', '__weakref__', '__hash__', '__eq__', '__ne__', '__lt__',
    '__le__', '__gt__', '__ge__', '__bool__', '__contains__', '__add__',
    '__sub__', '__mul__', '__truediv__', '__floordiv__', '__mod__', '__pow__',
    '__and__', '__or__', '__xor__', '__invert__', '__neg__', '__pos__',
    '__abs__', '__round__', '__index__', '__int__', '__float__', '__complex__',
    '__bytes__', '__format__', '__sizeof__', '__reduce__', '__reduce_ex__',
    '__copy__', '__deepcopy__', '__await__', '__aiter__', '__anext__',
    '__fspath__', '__set_name__', '__init_subclass__', '__class_getitem__',
    '__matmul__', '__rmatmul__', '__radd__', '__rsub__', '__rmul__',
    '__divmod__', '__rdivmod__', '__lshift__', '__rshift__',
    '__iadd__', '__isub__', '__imul__',
}

_SHL_SAFE_BUILTINS = {
    'print', 'len', 'range', 'str', 'int', 'float', 'bool', 'list', 'dict',
    'set', 'tuple', 'sorted', 'sum', 'min', 'max', 'abs', 'round', 'open',
    'enumerate', 'zip', 'map', 'filter', 'any', 'all', 'isinstance', 'getattr',
    'setattr', 'hasattr', 'repr', 'type', 'reversed', 'iter', 'next', 'chr',
    'ord', 'hex', 'oct', 'bin', 'input', 'format', 'divmod', 'pow', 'slice',
    'frozenset', 'bytes', 'bytearray', 'callable', 'vars', 'globals', 'locals',
}


class ShlVarCollector(ast.NodeVisitor):
    def __init__(self):
        self.shl_assigned: Set[str] = set()
        self.shl_globals: Set[str] = set()
        self.shl_nonlocals: Set[str] = set()
        self.shl_args: Set[str] = set()
        self.shl_imported: Set[str] = set()
        self.shl_defs: List[str] = []
        self.shl_class_vars: Set[str] = set()

    def visit_Global(self, shl_node):
        self.shl_globals.update(shl_node.names)

    def visit_Nonlocal(self, shl_node):
        self.shl_nonlocals.update(shl_node.names)

    def visit_Import(self, shl_node):
        for shl_a in shl_node.names:
            self.shl_imported.add(shl_a.asname or shl_a.name.split('.')[0])

    def visit_ImportFrom(self, shl_node):
        for shl_a in shl_node.names:
            if shl_a.name == '*':
                continue
            self.shl_imported.add(shl_a.asname or shl_a.name)

    def visit_FunctionDef(self, shl_node):
        self.shl_assigned.add(shl_node.name)
        self.shl_defs.append(shl_node.name)
        self._shl_collect_args(shl_node.args)
        self.generic_visit(shl_node)

    def visit_AsyncFunctionDef(self, shl_node):
        self.shl_assigned.add(shl_node.name)
        self.shl_defs.append(shl_node.name)
        self._shl_collect_args(shl_node.args)
        self.generic_visit(shl_node)

    def visit_ClassDef(self, shl_node):
        self.shl_assigned.add(shl_node.name)
        self.shl_defs.append(shl_node.name)
        self._shl_collect_class_vars(shl_node)
        self.generic_visit(shl_node)

    def _shl_collect_class_vars(self, shl_node):
        for shl_stmt in shl_node.body:
            if isinstance(shl_stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for shl_sub in ast.walk(shl_stmt):
                if isinstance(shl_sub, ast.Name) and isinstance(shl_sub.ctx, ast.Store):
                    self.shl_class_vars.add(shl_sub.id)

    def visit_Lambda(self, shl_node):
        self._shl_collect_args(shl_node.args)
        self.generic_visit(shl_node)

    def visit_ExceptHandler(self, shl_node):
        if shl_node.name:
            self.shl_assigned.add(shl_node.name)
            self.shl_args.add(shl_node.name)
        self.generic_visit(shl_node)

    def _shl_collect_args(self, shl_args):
        for shl_a in getattr(shl_args, 'posonlyargs', []):
            self.shl_args.add(shl_a.arg)
            self.shl_assigned.add(shl_a.arg)
        for shl_a in shl_args.args:
            self.shl_args.add(shl_a.arg)
            self.shl_assigned.add(shl_a.arg)
        for shl_a in shl_args.kwonlyargs:
            self.shl_args.add(shl_a.arg)
            self.shl_assigned.add(shl_a.arg)
        if shl_args.vararg is not None:
            self.shl_args.add(shl_args.vararg.arg)
            self.shl_assigned.add(shl_args.vararg.arg)
        if shl_args.kwarg is not None:
            self.shl_args.add(shl_args.kwarg.arg)
            self.shl_assigned.add(shl_args.kwarg.arg)

    def visit_Name(self, shl_node):
        if isinstance(shl_node.ctx, ast.Store):
            self.shl_assigned.add(shl_node.id)


class ShlVarRenamer(ast.NodeTransformer):
    def __init__(self, shl_assigned, shl_args, shl_globals, shl_nonlocals,
                 shl_imported=None, shl_defs=None, rename_defs=False,
                 shl_class_vars=None):
        self.shl_imported = set(shl_imported or ())
        self.shl_defs = list(shl_defs or ())
        self.shl_rename_defs = rename_defs
        shl_protected = (
            set(shl_args) | set(shl_globals) | set(shl_nonlocals)
            | self.shl_imported | set(shl_class_vars or ())
            | _SHL_DUNDER | _SHL_SAFE_BUILTINS
        )
        self.shl_rename = set(shl_assigned) - shl_protected
        if rename_defs:
            self.shl_rename |= {
                shl_d for shl_d in self.shl_defs
                if shl_d not in self.shl_imported and not shl_d.startswith('__')
            }
        else:
            self.shl_rename -= set(self.shl_defs)
        self.shl_map: Dict[str, str] = {}

    def _shl_new(self, shl_name):
        return 'shl_' + hashlib.shake_128(shl_name.encode()).hexdigest(8)

    def _shl_maybe(self, shl_name):
        if shl_name in self.shl_rename:
            self.shl_map.setdefault(shl_name, self._shl_new(shl_name))
            return self.shl_map[shl_name]
        return shl_name

    def visit_FunctionDef(self, shl_node):
        if self.shl_rename_defs:
            shl_node.name = self._shl_maybe(shl_node.name)
        self.generic_visit(shl_node)
        return shl_node

    def visit_AsyncFunctionDef(self, shl_node):
        if self.shl_rename_defs:
            shl_node.name = self._shl_maybe(shl_node.name)
        self.generic_visit(shl_node)
        return shl_node

    def visit_ClassDef(self, shl_node):
        self.generic_visit(shl_node)
        return shl_node

    def visit_Attribute(self, shl_node):
        self.generic_visit(shl_node)
        return shl_node

    def visit_arg(self, shl_node):
        return shl_node

    def visit_Name(self, shl_node):
        shl_node.id = self._shl_maybe(shl_node.id)
        return shl_node


class ShlFlowFlattener(ast.NodeTransformer):
    SHL_BLOCKED = (
        ast.Return, ast.Yield, ast.YieldFrom, ast.Try, ast.TryStar,
        ast.With, ast.AsyncWith, ast.Break, ast.Continue,
        ast.AsyncFunctionDef, ast.Global, ast.Nonlocal, ast.Lambda,
        ast.Match, ast.MatchValue, ast.Await,
    )

    def _shl_flatten(self, shl_node):
        self.generic_visit(shl_node)
        for shl_n in ast.walk(shl_node):
            if not isinstance(shl_n, self.SHL_BLOCKED):
                continue
            if isinstance(shl_n, ast.Return) and shl_n in shl_node.body:
                continue
            return shl_node
        if any(isinstance(shl_n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef))
               for shl_n in shl_node.body):
            return shl_node
        shl_original = list(shl_node.body)
        if not shl_original:
            return shl_node
        shl_state = f'_shl_st_{random.randint(1000, 9999)}'
        shl_body = [ast.Assign(
            targets=[ast.Name(id=shl_state, ctx=ast.Store())],
            value=ast.Constant(0)
        )]
        shl_while_body = []
        for shl_i, shl_stmt in enumerate(shl_original):
            shl_while_body.append(ast.If(
                test=ast.Compare(
                    left=ast.Name(id=shl_state, ctx=ast.Load()),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(shl_i)]
                ),
                body=[
                    shl_stmt,
                    ast.AugAssign(
                        target=ast.Name(id=shl_state, ctx=ast.Store()),
                        op=ast.Add(),
                        value=ast.Constant(1)
                    )
                ],
                orelse=[]
            ))
        shl_body.append(ast.While(
            test=ast.Compare(
                left=ast.Name(id=shl_state, ctx=ast.Load()),
                ops=[ast.Lt()],
                comparators=[ast.Constant(len(shl_original))]
            ),
            body=shl_while_body,
            orelse=[]
        ))
        shl_node.body = shl_body
        return shl_node

    def visit_FunctionDef(self, shl_node):
        return self._shl_flatten(shl_node)

    def visit_AsyncFunctionDef(self, shl_node):
        return self._shl_flatten(shl_node)


class ShlStrEncryptor(ast.NodeTransformer):
    def __init__(self, shl_key):
        self.shl_key = shl_key
        self.shl_in_fstr = False

    def visit_JoinedStr(self, shl_node):
        shl_old = self.shl_in_fstr
        self.shl_in_fstr = True
        self.generic_visit(shl_node)
        self.shl_in_fstr = shl_old
        return shl_node

    def visit_MatchValue(self, shl_node):
        return shl_node

    def visit_MatchMapping(self, shl_node):
        for shl_pat in shl_node.patterns:
            self.visit(shl_pat)
        return shl_node

    def _shl_enc(self, shl_data):
        shl_iv = random.randbytes(16)
        return shl_iv + encrypt_cbc(self.shl_key, shl_iv, shl_data)

    def visit_Constant(self, shl_node):
        if self.shl_in_fstr:
            return shl_node
        if isinstance(shl_node.value, str):
            return ast.Call(
                func=ast.Name(id='_shl_dec_str', ctx=ast.Load()),
                args=[ast.Constant(self._shl_enc(shl_node.value.encode('utf-8')))],
                keywords=[]
            )
        if isinstance(shl_node.value, (bytes, bytearray)):
            return ast.Call(
                func=ast.Name(id='_shl_dec_bytes', ctx=ast.Load()),
                args=[ast.Constant(self._shl_enc(bytes(shl_node.value)))],
                keywords=[]
            )
        return shl_node


class ShlUnusedCleaner(ast.NodeTransformer):
    def visit_FunctionDef(self, shl_node):
        self.generic_visit(shl_node)
        shl_node.body = self._shl_clean(shl_node.body)
        return shl_node

    def visit_AsyncFunctionDef(self, shl_node):
        self.generic_visit(shl_node)
        shl_node.body = self._shl_clean(shl_node.body)
        return shl_node

    def visit_ClassDef(self, shl_node):
        self.generic_visit(shl_node)
        shl_node.body = self._shl_clean(shl_node.body, shl_keep_doc=True)
        return shl_node

    def visit_If(self, shl_node):
        self.generic_visit(shl_node)
        if isinstance(shl_node.test, ast.Constant):
            shl_node.body = self._shl_clean(shl_node.body)
            shl_node.orelse = self._shl_clean(shl_node.orelse)
        return shl_node

    @staticmethod
    def _shl_is_docstring(stl_body, stl_index):
        if stl_index != 0 or not stl_body:
            return False
        stl_first = stl_body[0]
        if not isinstance(stl_first, ast.Expr):
            return False
        stl_val = stl_first.value
        if isinstance(stl_val, ast.Constant) and isinstance(stl_val.value, str):
            return True
        return isinstance(stl_val, ast.Call) and isinstance(stl_val.func, ast.Name) \
            and stl_val.func.id == '_shl_dec_str'

    def _shl_clean(self, stl_body, shl_keep_doc=False):
        stl_out = []
        for stl_i, stl_stmt in enumerate(stl_body):
            if not shl_keep_doc and self._shl_is_docstring(stl_body, stl_i):
                continue
            if isinstance(stl_stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                stl_out.append(stl_stmt)
                continue
            if isinstance(stl_stmt, ast.If) and isinstance(stl_stmt.test, ast.Constant):
                stl_branch = stl_stmt.body if stl_stmt.test.value else stl_stmt.orelse
                stl_out.extend(self._shl_clean(stl_branch))
                continue
            stl_out.append(stl_stmt)
        return stl_out or [ast.Pass()]


def shll_transform(shl_source, shl_key, rename_defs=False):
    shl_tree = ast.parse(shl_source)
    shl_vc = ShlVarCollector()
    shl_vc.visit(shl_tree)

    shl_flattener = ShlFlowFlattener()
    shl_tree = shl_flattener.visit(shl_tree)

    shl_renamer = ShlVarRenamer(
        shl_vc.shl_assigned, shl_vc.shl_args, shl_vc.shl_globals,
        shl_vc.shl_nonlocals, shl_vc.shl_imported, shl_vc.shl_defs,
        rename_defs=rename_defs, shl_class_vars=shl_vc.shl_class_vars,
    )
    shl_tree = shl_renamer.visit(shl_tree)

    shl_str_enc = ShlStrEncryptor(shl_key)
    shl_tree = shl_str_enc.visit(shl_tree)

    shl_cleaner = ShlUnusedCleaner()
    shl_tree = shl_cleaner.visit(shl_tree)

    ast.fix_missing_locations(shl_tree)
    return ast.unparse(shl_tree)

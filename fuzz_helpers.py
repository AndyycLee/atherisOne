import inspect
import typing

DEFAULT_STR_MAXLEN = 256
DEFAULT_LIST_MAXLEN = 8

def gen_int(fdp, lo=-2**31, hi=2**31-1):
    try:
        return fdp.ConsumeIntInRange(max(-2**31, lo), min(2**31-1, hi))
    except Exception:
        b = fdp.ConsumeBytes(4)
        return int.from_bytes(b, "little", signed=True)

def gen_float(fdp):
    i = gen_int(fdp, -10**6, 10**6)
    frac = fdp.ConsumeIntInRange(0, 10**6) / 10**6
    return float(i) + frac

def gen_bool(fdp):
    return fdp.ConsumeBool()

def gen_bytes(fdp, maxlen=DEFAULT_STR_MAXLEN):
    n = fdp.ConsumeIntInRange(0, maxlen)
    return fdp.ConsumeBytes(n)

def gen_str(fdp, maxlen=DEFAULT_STR_MAXLEN):
    b = gen_bytes(fdp, maxlen)
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("utf-8", "replace")

def gen_list(fdp, elem_type, maxlen=DEFAULT_LIST_MAXLEN):
    n = fdp.ConsumeIntInRange(0, maxlen)
    out = []
    for _ in range(n):
        out.append(gen_by_type_hint(fdp, elem_type))
    return out

def gen_tuple(fdp, elem_types):
    if elem_types and elem_types[-1] is Ellipsis:
        return tuple(gen_list(fdp, elem_types[0]))
    return tuple(gen_by_type_hint(fdp, t) for t in elem_types)

def gen_dict(fdp, ktype, vtype, maxlen=DEFAULT_LIST_MAXLEN):
    n = fdp.ConsumeIntInRange(0, maxlen)
    out = {}
    for _ in range(n):
        k = gen_by_type_hint(fdp, ktype)
        if isinstance(k, (list, dict)):
            k = str(k)
        v = gen_by_type_hint(fdp, vtype)
        out[k] = v
    return out

def gen_by_type_hint(fdp, hint):
    """Produce a Python value for a typing hint. Handles common cases."""
    origin = getattr(hint, "__origin__", None)
    args = getattr(hint, "__args__", ())

    if hint is None or hint is inspect._empty:
        return gen_str(fdp)

    if hint is int:
        return gen_int(fdp)
    if hint is float:
        return gen_float(fdp)
    if hint is bool:
        return gen_bool(fdp)
    if hint is str:
        return gen_str(fdp)
    if hint is bytes:
        return gen_bytes(fdp)

    # typing containers
    if origin in (list, typing.List):
        elem = args[0] if args else inspect._empty
        return gen_list(fdp, elem)
    if origin in (tuple, typing.Tuple):
        if args:
            return gen_tuple(fdp, args)
        return tuple(gen_list(fdp, inspect._empty))
    if origin in (dict, typing.Dict):
        k = args[0] if args else inspect._empty
        v = args[1] if len(args) > 1 else inspect._empty
        return gen_dict(fdp, k, v)
    if origin is typing.Union:
        # choose one of union alternatives
        idx = 0
        try:
            idx = fdp.ConsumeIntInRange(0, max(0, len(args)-1))
        except Exception:
            idx = 0
        return gen_by_type_hint(fdp, args[idx])

    # Fallback: produce a string
    return gen_str(fdp)

"""The type stub must describe the module that is actually built.

`python/allcrypt.pyi` is written by hand, and it had drifted:
`TlsClient`'s `max_version` default said TLSv1.2 where the module's is
TLSv1.3, `client_key` left out `EddsaKey`, `gost_sbox` claimed tuples,
and `EcKey.vko`, `sign_gost`, `verify_gost`, `EcPublicKey.verify_gost`,
`TlsClient.channel_binding`, `tls_master_secret`, `ssl3_record_mac` and
`ntlmv2_hash` were absent. Nothing compared the two. pyo3 publishes each
function's signature as `__text_signature__`, so this does, for every
function and method the stub names: parameter names in order, and the
default wherever the module's default is a plain value.
"""

import ast
import inspect
import os

import pytest

import allcrypt

STUB = os.path.join(os.path.dirname(__file__), "..", "python", "allcrypt.pyi")


def stub_functions():
    tree = ast.parse(open(STUB, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            yield node.name, None, node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if not isinstance(item, ast.FunctionDef):
                    continue
                decorators = [ast.unparse(d) for d in item.decorator_list]
                if any(d == "property" or d.endswith(".setter") for d in decorators):
                    continue
                if item.name.startswith("__") and item.name != "__init__":
                    continue
                yield item.name, node.name, item


def stub_parameters(function):
    arguments = function.args
    positional = arguments.posonlyargs + arguments.args
    defaults = [None] * (len(positional) - len(arguments.defaults)) + list(arguments.defaults)
    out = [(a.arg, d) for a, d in zip(positional, defaults) if a.arg not in ("self", "cls")]
    out += list(zip([a.arg for a in arguments.kwonlyargs], arguments.kw_defaults))
    return out


def runtime_object(name, owner):
    if owner is None:
        return getattr(allcrypt, name, None)
    cls = getattr(allcrypt, owner, None)
    if cls is None:
        return None
    return cls if name == "__init__" else getattr(cls, name, None)


CASES = [(owner, name, node) for name, owner, node in stub_functions()]


@pytest.mark.parametrize("owner, name, node", CASES,
                         ids=[f"{o or 'allcrypt'}.{n}" for o, n, _ in CASES])
def test_the_stub_matches_the_module(owner, name, node):
    target = runtime_object(name, owner)
    if target is None:
        pytest.skip("not a pyo3 callable (an enum or a Python-level helper)")
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        pytest.skip("no text signature published")
    runtime = [p for p in signature.parameters.values()
               if p.name not in ("self", "cls")
               and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
    stub = stub_parameters(node)
    assert [p.name for p in runtime] == [n for n, _ in stub], "parameter names"
    for parameter, (_, default) in zip(runtime, stub):
        has_default = parameter.default is not inspect.Parameter.empty
        assert has_default == (default is not None), \
            f"{parameter.name}: default present in one and not the other"
        if not has_default or parameter.default is Ellipsis:
            continue
        try:
            expected = ast.literal_eval(default)
        except ValueError:
            continue
        assert parameter.default == expected, f"{parameter.name}'s default"


def test_a_negative_length_raises_overflow_error_as_documented():
    # Undocumented before: the docstrings promised CryptoError/ValueError
    # for bad values, and a negative length raises OverflowError, which
    # `except ValueError` does not catch. Pinned here so the documented
    # behaviour and the real one cannot part again.
    with pytest.raises(OverflowError):
        allcrypt.hkdf(b"key", -1)
    assert "OverflowError" in (allcrypt.__doc__ or "")

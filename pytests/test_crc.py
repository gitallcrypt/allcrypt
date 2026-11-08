"""CRCs from their parameters through the Python bindings, against
vectors/crc.vec (written by scripts/make_crc_vectors.py; pycrc, crccheck,
crcmod and the crc crate agreeing). The Rust tests hold every row in every
way; this checks the binding: `crc`, `crc_parameters`, `new` by the
catalogue's names and by a model line, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "crc.vec")


def read():
    messages, models, rows = [], [], []
    with open(VECTORS) as f:
        for line in f:
            kind = line.split(" ", 1)[0]
            if kind == "#":
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            if kind == "msg":
                messages.append(b"" if fields["data"] == "-" else bytes.fromhex(fields["data"]))
            elif kind == "model":
                models.append({"name": fields["name"], "width": int(fields["width"]),
                               "poly": int(fields["poly"], 16), "init": int(fields["init"], 16),
                               "refin": fields["refin"] == "1",
                               "refout": fields["refout"] == "1",
                               "xorout": int(fields["xorout"], 16)})
            else:
                rows.append((models[int(fields["model"])], messages[int(fields["msg"])],
                             fields["value"]))
    assert (len(messages), len(models), len(rows)) == (26, 368, 4960)
    return models, rows


MODELS, ROWS = read()
PARAMS = ("width", "poly", "init", "refin", "refout", "xorout")


def test_the_catalogue_names_are_checksums():
    named = [m["name"] for m in MODELS if m["name"] != "-"]
    assert len(named) == 112
    assert allcrypt.checksums_available[32:] == named
    for model in MODELS:
        if model["name"] == "-":
            continue
        entry = allcrypt.crc_parameters(model["name"].upper())
        assert entry["name"].lower() == model["name"]
        assert {k: entry[k] for k in PARAMS} == {k: model[k] for k in PARAMS}
        h = allcrypt.crc(**{k: model[k] for k in PARAMS}, data=b"123456789")
        assert int(h.hexdigest(), 16) == entry["check"]


def test_every_row():
    for model, message, value in ROWS:
        params = {k: model[k] for k in PARAMS}
        h = allcrypt.crc(**params, data=message)
        assert h.hexdigest() == value, h.name
        assert h.digest_size == len(value) // 2
        again = allcrypt.new(h.name)
        for at in range(0, len(message), 5):
            again.update(memoryview(message)[at:at + 5])
        assert again.hexdigest() == value
        if model["name"] != "-":
            by_name = allcrypt.new(model["name"], message)
            assert by_name.name == model["name"]
            assert by_name.hexdigest() == value


def test_the_name_is_the_model_line():
    h = allcrypt.crc(16, 0x8005, refin=True, refout=True)
    assert h.name == "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000"
    assert allcrypt.new("CRC-16/ARC").name == "crc-16/arc"
    assert allcrypt.new("crc_16/arc").name == "crc-16/arc"


@pytest.mark.parametrize("params", [
    {"width": 0, "poly": 1}, {"width": 129, "poly": 1}, {"width": 8, "poly": 0x107},
    {"width": 8, "poly": 7, "init": 0x100}, {"width": 8, "poly": 7, "xorout": 0x100},
])
def test_bad_parameters_are_refused(params):
    with pytest.raises(ValueError):
        allcrypt.crc(**params)


def test_unknown_names_are_refused():
    with pytest.raises(ValueError, match="not in the CRC catalogue"):
        allcrypt.crc_parameters("crc-16/nonesuch")
    with pytest.raises(ValueError):
        allcrypt.new("crc-16/nonesuch")
    with pytest.raises(ValueError):
        allcrypt.new("width=8 poly=0x07")

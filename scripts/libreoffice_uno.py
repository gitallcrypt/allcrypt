"""LibreOffice, headless and driven through UNO, for the check scripts
that use it as a witness (`check_office.py`, `check_odf.py`).

It runs with a profile of its own in a temporary directory, so nothing
it is told - a configuration change included - outlives the check.
Needs `python3-uno`, which is how the system's `soffice` is driven.

**A development tool, not a test.**
"""

import os
import subprocess
import time

CONTENT = {"swriter": "A document LibreOffice wrote, with a password.",
           "scalc": "A cell in a spreadsheet",
           "simpress": "A slide"}


class LibreOffice:
    """One headless LibreOffice, driven through UNO."""

    def __init__(self, work):
        import uno  # noqa: F401 - python3-uno
        self.uno = uno
        self.profile = os.path.join(work, "lo-profile")
        self.port = 2083
        self.process = subprocess.Popen(
            ["soffice", "--headless", "--invisible", "--norestore", "--nologo",
             f"--accept=socket,host=127.0.0.1,port={self.port};urp;",
             f"-env:UserInstallation=file://{self.profile}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        local = uno.getComponentContext()
        resolver = local.ServiceManager.createInstanceWithContext(
            "com.sun.star.bridge.UnoUrlResolver", local)
        for _ in range(90):
            try:
                context = resolver.resolve(f"uno:socket,host=127.0.0.1,port={self.port};urp;"
                                           "StarOffice.ComponentContext")
                break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("LibreOffice did not start")
        self.desktop_context = context
        self.desktop = context.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", context)

    def prop(self, name, value):
        from com.sun.star.beans import PropertyValue
        p = PropertyValue()
        p.Name = name
        p.Value = value
        return p

    def url(self, path):
        return self.uno.systemPathToFileUrl(os.path.abspath(path))

    def make(self, kind, path, filter_name, password=None, picture=None):
        """A new document of `kind` with known content, saved; a Writer
        document can carry a picture, which a .doc keeps in its Data
        stream."""
        doc = self.desktop.loadComponentFromURL(f"private:factory/{kind}", "_blank", 0,
                                                (self.prop("Hidden", True),))
        if kind == "swriter":
            doc.Text.setString(CONTENT["swriter"])
            if picture:
                provider = self.desktop_context.ServiceManager.createInstanceWithContext(
                    "com.sun.star.graphic.GraphicProvider", self.desktop_context)
                graphic = provider.queryGraphic((self.prop("URL", self.url(picture)),))
                shape = doc.createInstance("com.sun.star.text.TextGraphicObject")
                shape.Graphic = graphic
                # Inline, as a character: Word keeps such a picture in
                # the Data stream, and a floating one elsewhere.
                shape.AnchorType = self.uno.Enum("com.sun.star.text.TextContentAnchorType",
                                                 "AS_CHARACTER")
                doc.Text.insertTextContent(doc.Text.getEnd(), shape, False)
        elif kind == "scalc":
            doc.Sheets.getByIndex(0).getCellByPosition(0, 0).setString(CONTENT["scalc"])
        else:
            page = doc.DrawPages.getByIndex(0)
            shape = doc.createInstance("com.sun.star.drawing.TextShape")
            page.add(shape)
            shape.setString(CONTENT["simpress"])
        props = [self.prop("FilterName", filter_name)]
        if password:
            props.append(self.prop("Password", password))
        doc.storeToURL(self.url(path), tuple(props))
        doc.close(True)

    def read(self, path, password=None):
        """The content LibreOffice finds, or None when it will not open
        the file."""
        props = [self.prop("Hidden", True)]
        if password is not None:
            props.append(self.prop("Password", password))
        try:
            doc = self.desktop.loadComponentFromURL(self.url(path), "_blank", 0, tuple(props))
        except Exception:
            return None
        if doc is None:
            return None
        try:
            if doc.supportsService("com.sun.star.text.TextDocument"):
                return doc.Text.getString()
            if doc.supportsService("com.sun.star.sheet.SpreadsheetDocument"):
                return doc.Sheets.getByIndex(0).getCellByPosition(0, 0).getString()
            page = doc.DrawPages.getByIndex(0)
            return "".join(page.getByIndex(i).getString() for i in range(page.getCount())
                           if hasattr(page.getByIndex(i), "getString"))
        finally:
            doc.close(True)

    def close(self):
        try:
            self.desktop.terminate()
        except Exception:
            pass
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def configure(self, path, name, value):
        """Set a configuration value in this LibreOffice's own profile."""
        provider = self.desktop_context.ServiceManager.createInstanceWithContext(
            "com.sun.star.configuration.ConfigurationProvider", self.desktop_context)
        node = provider.createInstanceWithArguments(
            "com.sun.star.configuration.ConfigurationUpdateAccess",
            (self.prop("nodepath", path),))
        node.setPropertyValue(name, value)
        node.commitChanges()


def write_png(path, width=64, height=48):
    """A small picture of noise, so that it does not compress away."""
    import random
    import struct
    import zlib
    choose = random.Random(7)
    rows = b"".join(b"\x00" + bytes(choose.randrange(256) for _ in range(3 * width))
                    for _ in range(height))

    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))

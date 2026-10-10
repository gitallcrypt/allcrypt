//! The XML document inside a KDBX file: groups, entries, protected
//! values and attachments.
//!
//! **Protected values are one stream, in document order.** Each
//! `Protected="True"` element's text is base64 of the value XORed with
//! the next bytes of the inner stream, so they can only be decrypted in
//! the order they appear - a value skipped, or a history entry visited
//! out of turn, puts every later value under the wrong keystream, and
//! the error shows as garbage in some *other* field.
//!
//! Attachments live outside the entries: in `Meta/Binaries` (KDBX 3.1,
//! base64, perhaps gzipped) or the inner header (KDBX 4), and an entry
//! holds `<Binary><Key>name</Key><Value Ref="n"/></Binary>`.

use crate::kdbx::{self, InnerBinary, InnerStream, Opened};
use crate::xml::{Element, Node};
use crate::{base64, hex};

#[derive(Clone, PartialEq)]
pub struct Field {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

/// A protected field's value - the password, normally - is not printed.
impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Field");
        d.field("key", &self.key);
        if self.protected {
            d.field("value", &crate::hidden::Hidden);
        } else {
            d.field("value", &self.value);
        }
        d.field("protected", &self.protected).finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub fields: Vec<Field>,
    pub attachments: Vec<(String, Vec<u8>)>,
    pub history: usize,
}

impl Entry {
    pub fn field(&self, key: &str) -> &str {
        self.fields.iter().find(|f| f.key == key).map(|f| f.value.as_str()).unwrap_or("")
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Group {
    pub name: String,
    pub entries: Vec<Entry>,
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Database {
    pub name: String,
    pub groups: Vec<Group>,
}

fn is_true(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Decrypt every protected element in document order, in place. A
/// protected `Value` becomes its text; anything else protected (an old
/// file's attachment) becomes base64 of its bytes, as an unprotected
/// one would be.
fn unprotect(element: &mut Element, stream: &mut InnerStream) -> Result<(), String> {
    if is_true(element.attribute("Protected")) {
        let raw = base64::decode(&element.text()).ok_or("A protected value is not base64.")?;
        let plain = stream.apply(&raw);
        let text = if element.name == "Value" {
            String::from_utf8(plain).map_err(|_| "A protected value is not UTF-8 after \
                                                 decryption: the inner stream is wrong.")?
        } else {
            base64::encode(&plain)
        };
        element.children = vec![Node::Text(text)];
        element.attributes.retain(|(name, _)| name != "Protected");
        element.attributes.push(("ProtectInMemory".to_string(), "True".to_string()));
        return Ok(());
    }
    for child in element.elements_mut() {
        unprotect(child, stream)?;
    }
    Ok(())
}

fn read_entry(element: &Element, binaries: &[Vec<u8>]) -> Result<Entry, String> {
    let mut entry = Entry::default();
    for string in element.children_named("String") {
        let value = string.child("Value");
        entry.fields.push(Field {
            key: string.child_text("Key"),
            value: value.map(Element::text).unwrap_or_default(),
            protected: value.is_some_and(|v| is_true(v.attribute("ProtectInMemory"))),
        });
    }
    for binary in element.children_named("Binary") {
        let name = binary.child_text("Key");
        let value = binary.child("Value").ok_or("An attachment with no Value.")?;
        let data = match value.attribute("Ref") {
            Some(reference) => {
                let index: usize = reference.parse().map_err(|_| "An attachment Ref is not a number.")?;
                binaries.get(index).cloned().ok_or(format!("Attachment {name:?} refers to \
                                                            binary {index}, which is not there."))?
            }
            None => base64::decode(&value.text()).ok_or("An inline attachment is not base64.")?,
        };
        entry.attachments.push((name, data));
    }
    entry.history = element.child("History").map_or(0, |h| h.children_named("Entry").count());
    Ok(entry)
}

fn read_group(element: &Element, binaries: &[Vec<u8>]) -> Result<Group, String> {
    Ok(Group {
        name: element.child_text("Name"),
        entries: element.children_named("Entry").map(|e| read_entry(e, binaries))
            .collect::<Result<_, _>>()?,
        groups: element.children_named("Group").map(|g| read_group(g, binaries))
            .collect::<Result<_, _>>()?,
    })
}

/// KDBX 3.1's attachments, by ID.
fn meta_binaries(meta: &Element) -> Result<Vec<Vec<u8>>, String> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if let Some(list) = meta.child("Binaries") {
        for binary in list.children_named("Binary") {
            let id: usize = binary.attribute("ID").and_then(|i| i.parse().ok())
                .ok_or("A binary without a numeric ID.")?;
            let mut data = base64::decode(&binary.text()).ok_or("A binary is not base64.")?;
            // KeePass never compresses an attachment it protects with the
            // inner stream, and ignores the Compressed flag on one when
            // reading; kdbxweb writes the flag anyway.
            // And an empty attachment is empty whatever the flag says:
            // KeePass writes `<Binary ID="0" Compressed="True"/>` for one.
            if is_true(binary.attribute("Compressed"))
                && !is_true(binary.attribute("ProtectInMemory")) && !data.is_empty() {
                data = kdbx::gunzip(&data)?;
            }
            if out.len() <= id {
                out.resize(id + 1, Vec::new());
            }
            out[id] = data;
        }
    }
    Ok(out)
}

#[derive(Debug)]
pub struct Read {
    pub database: Database,
    /// For a KDBX 3.1 file: whether `Meta/HeaderHash` was present, and
    /// if so it has been checked.
    pub header_hash_checked: bool,
}

pub fn read(mut opened: Opened) -> Result<Read, String> {
    let mut root = crate::xml::parse(&opened.xml)?;
    if root.name != "KeePassFile" {
        return Err(format!("The document is <{}>, not <KeePassFile>.", root.name));
    }
    unprotect(&mut root, &mut opened.stream)?;
    let meta = root.child("Meta").ok_or("A document with no Meta.")?;
    let mut header_hash_checked = false;
    if opened.header.major < 4 {
        let stored = meta.child_text("HeaderHash");
        if !stored.is_empty() {
            if base64::decode(&stored).as_deref() != Some(&opened.header_hash[..]) {
                return Err("Meta/HeaderHash does not match the header: it was changed."
                    .to_string());
            }
            header_hash_checked = true;
        }
    }
    let binaries = if opened.header.major >= 4 {
        opened.binaries.iter().map(|b| b.data.clone()).collect()
    } else {
        meta_binaries(meta)?
    };
    let tree = root.child("Root").ok_or("A document with no Root.")?;
    Ok(Read {
        database: Database {
            name: meta.child_text("DatabaseName"),
            groups: tree.children_named("Group").map(|g| read_group(g, &binaries))
                .collect::<Result<_, _>>()?,
        },
        header_hash_checked,
    })
}

// -------------------------------------------------------- canonical dump --

fn dump_group(group: &Group, path: &str, out: &mut String) {
    let path = format!("{path}/{}", group.name);
    out.push_str(&format!("group {path}\n"));
    for entry in &group.entries {
        out.push_str(&format!("entry {path}\n"));
        let mut fields: Vec<&Field> = entry.fields.iter().collect();
        fields.sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
        for field in fields {
            out.push_str(&format!("  string {} {}\n", hex(field.key.as_bytes()),
                                  hex(field.value.as_bytes())));
        }
        for (name, data) in &entry.attachments {
            out.push_str(&format!("  attachment {} {}\n", hex(name.as_bytes()),
                                  hex(&kdbx::sha256(&[data]))));
        }
        out.push_str(&format!("  history {}\n", entry.history));
    }
    for child in &group.groups {
        dump_group(child, &path, out);
    }
}

/// The listing `scripts/witness/kdbxwitness dump` prints, so that the
/// two can be compared as text.
pub fn canonical(header: &kdbx::Header, database: &Database) -> String {
    let mut out = format!("version {}.{}\ncipher {}\nkdf {}\ncompression {}\nname {}\n",
                          header.major, header.minor, header.cipher.name(), header.kdf.name(),
                          u8::from(header.compressed), hex(database.name.as_bytes()));
    for group in &database.groups {
        dump_group(group, "", &mut out);
    }
    out
}

// --------------------------------------------------------------- writing --

fn uuid() -> Result<String, String> {
    Ok(base64::encode(&allcrypt::api::random_bytes(16)?))
}

fn times(major: u16) -> Element {
    // KDBX 4 writes a time as base64 of the seconds since 0001-01-01,
    // 64-bit little endian; KDBX 3.1 as ISO 8601.
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let stamp = if major >= 4 {
        base64::encode(&(unix + 62_135_596_800).to_le_bytes())
    } else {
        crate::iso8601(unix)
    };
    let mut element = Element::new("Times");
    for name in ["CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime",
                 "LocationChanged"] {
        element.push(Element::new(name).with_text(&stamp));
    }
    element.push(Element::new("Expires").with_text("False"));
    element.push(Element::new("UsageCount").with_text("0"));
    element
}

struct Writer<'a> {
    major: u16,
    stream: &'a mut InnerStream,
    binaries: Vec<Vec<u8>>,
}

impl Writer<'_> {
    fn entry(&mut self, entry: &Entry) -> Result<Element, String> {
        let mut element = Element::new("Entry").with_child(Element::new("UUID").with_text(&uuid()?))
            .with_child(times(self.major));
        for field in &entry.fields {
            let value = if field.protected {
                let hidden = self.stream.apply(field.value.as_bytes());
                Element::new("Value").with_attribute("Protected", "True")
                    .with_text(&base64::encode(&hidden))
            } else {
                Element::new("Value").with_text(&field.value)
            };
            element.push(Element::new("String")
                .with_child(Element::new("Key").with_text(&field.key))
                .with_child(value));
        }
        for (name, data) in &entry.attachments {
            let index = match self.binaries.iter().position(|b| b == data) {
                Some(index) => index,
                None => {
                    self.binaries.push(data.clone());
                    self.binaries.len() - 1
                }
            };
            element.push(Element::new("Binary")
                .with_child(Element::new("Key").with_text(name))
                .with_child(Element::new("Value").with_attribute("Ref", &index.to_string())));
        }
        Ok(element)
    }

    fn group(&mut self, group: &Group) -> Result<Element, String> {
        let mut element = Element::new("Group").with_child(Element::new("UUID").with_text(&uuid()?))
            .with_child(Element::new("Name").with_text(&group.name))
            .with_child(times(self.major));
        for entry in &group.entries {
            element.push(self.entry(entry)?);
        }
        for child in &group.groups {
            element.push(self.group(child)?);
        }
        Ok(element)
    }
}

/// Write `database` under `plan`.
pub fn write(database: &Database, plan: &kdbx::Plan, credentials: &kdbx::Credentials)
             -> Result<Vec<u8>, String> {
    let header = kdbx::new_header(plan)?;
    let stream_key = if plan.major >= 4 {
        allcrypt::api::random_bytes(64)?
    } else {
        header.protected_stream_key.clone()
    };
    let mut stream = InnerStream::new(plan.inner_stream, &stream_key)?;
    let mut writer = Writer { major: plan.major, stream: &mut stream, binaries: Vec::new() };
    let mut tree = Element::new("Root");
    for group in &database.groups {
        tree.push(writer.group(group)?);
    }
    tree.push(Element::new("DeletedObjects"));
    let binaries = std::mem::take(&mut writer.binaries);

    let mut meta = Element::new("Meta").with_child(Element::new("Generator").with_text("allcrypt"));
    if plan.major < 4 {
        meta.push(Element::new("HeaderHash")
            .with_text(&base64::encode(&kdbx::header_hash(&header))));
    }
    meta.push(Element::new("DatabaseName").with_text(&database.name));
    let mut protection = Element::new("MemoryProtection");
    for (name, on) in [("ProtectTitle", false), ("ProtectUserName", false),
                       ("ProtectPassword", true), ("ProtectURL", false), ("ProtectNotes", false)] {
        protection.push(Element::new(name).with_text(if on { "True" } else { "False" }));
    }
    meta.push(protection);
    if plan.major < 4 && !binaries.is_empty() {
        let mut list = Element::new("Binaries");
        for (id, data) in binaries.iter().enumerate() {
            list.push(Element::new("Binary").with_attribute("ID", &id.to_string())
                .with_attribute("Compressed", "False").with_text(&base64::encode(data)));
        }
        meta.push(list);
    }
    let document = Element::new("KeePassFile").with_child(meta).with_child(tree);
    let inner: Vec<InnerBinary> = if plan.major >= 4 {
        binaries.into_iter().map(|data| InnerBinary { protected: false, data }).collect()
    } else {
        Vec::new()
    };
    kdbx::seal(&header, credentials, &crate::xml::write(&document), &stream_key, &inner)
}

/// The sample every check writes: the same content
/// `kdbxwitness create` writes, so that a database made by either
/// lists identically.
pub fn sample() -> Database {
    let field = |key: &str, value: &str, protected: bool| Field {
        key: key.to_string(), value: value.to_string(), protected,
    };
    let mail = Entry {
        fields: vec![
            field("Title", "Mail account", false),
            field("UserName", "alice@example.org", false),
            field("Password", "correct horse battery staple", true),
            field("URL", "https://mail.example.org/?a=1&b=<2>", false),
            field("Notes", "line one\nline two\n\ttabbed 'quoted' \"double\"", false),
        ],
        attachments: vec![("notes.bin".to_string(),
                           b"attachment contents\x00\x01\x02 binary".to_vec())],
        history: 0,
    };
    let card = Entry {
        fields: vec![
            field("Title", "Bank card", false),
            field("UserName", "", false),
            field("Password", "1234", true),
            field("PIN (custom)", "0000 \u{e9}\u{e8} \u{2603}", true),
            field("Notes", "", false),
        ],
        ..Entry::default()
    };
    let plain = Entry {
        fields: vec![field("Title", "Plain entry", false),
                     field("Password", "not protected", false)],
        ..Entry::default()
    };
    Database {
        name: "Sample <&> \"database\"".to_string(),
        groups: vec![Group {
            name: "Root".to_string(),
            entries: vec![plain],
            groups: vec![
                Group { name: "Email".to_string(), entries: vec![mail], groups: vec![] },
                Group { name: "Banking & Finance".to_string(), entries: vec![card],
                        groups: vec![] },
            ],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KeePass writes a zero-length attachment as an empty element still
    /// marked compressed; it is empty, not a gzip stream to refuse.
    #[test]
    fn test_an_empty_compressed_attachment_is_empty() {
        let meta = crate::xml::parse(b"<Meta><Binaries><Binary ID=\"0\" Compressed=\"True\"/>\
                                        <Binary ID=\"1\">aGk=</Binary></Binaries></Meta>")
            .unwrap();
        assert_eq!(meta_binaries(&meta).unwrap(), vec![Vec::new(), b"hi".to_vec()]);
    }

    /// A protected attachment is never compressed, whatever its flag:
    /// KeePass ignores `Compressed` on one, and kdbxweb sets it.
    #[test]
    fn test_a_protected_attachment_ignores_its_compressed_flag() {
        let key = [6u8; 32];
        let hidden = base64::encode(&InnerStream::new(2, &key).unwrap().apply(b"not gzip"));
        let doc = format!("<Meta><Binaries><Binary ID=\"0\" Compressed=\"True\" \
                           Protected=\"True\">{hidden}</Binary></Binaries></Meta>");
        let mut meta = crate::xml::parse(doc.as_bytes()).unwrap();
        unprotect(&mut meta, &mut InnerStream::new(2, &key).unwrap()).unwrap();
        assert_eq!(meta_binaries(&meta).unwrap(), vec![b"not gzip".to_vec()]);
    }

    /// The inner stream runs through the document in order, history
    /// entries included: a value read out of turn decrypts to garbage.
    #[test]
    fn test_protected_values_are_decrypted_in_document_order() {
        let key = [5u8; 32];
        let mut writer_stream = InnerStream::new(2, &key).unwrap();
        let first = base64::encode(&writer_stream.apply(b"first"));
        let second = base64::encode(&writer_stream.apply(b"second"));
        let doc = format!("<E><Value Protected=\"True\">{first}</Value><History><Value \
                           Protected=\"True\">{second}</Value></History></E>");
        let mut root = crate::xml::parse(doc.as_bytes()).unwrap();
        unprotect(&mut root, &mut InnerStream::new(2, &key).unwrap()).unwrap();
        assert_eq!(root.child_text("Value"), "first");
        assert_eq!(root.child("History").unwrap().child_text("Value"), "second");
    }
}

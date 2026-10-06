//! Just enough of Java object serialization to carry a JCEKS secret
//! key: a `SealedObjectForKeyProtector` holding an encrypted, serialized
//! `SecretKeySpec`.
//!
//! The reader takes the general grammar - class descriptors, handles and
//! back-references, strings, arrays, objects with fields - because a
//! JCEKS file gives no length for the object and the only way to find
//! the next entry is to read this one to its end. It refuses what these
//! objects never contain: custom `writeObject` data, enums, externalized
//! classes. The writer writes the two objects JCEKS needs, field for
//! field as the JDK writes them, with the classes' serialVersionUIDs
//! taken from the JDK's source; a test holds both to keytool's bytes.

const MAGIC: [u8; 4] = [0xac, 0xed, 0x00, 0x05];
const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_ENDBLOCKDATA: u8 = 0x78;
const BASE_HANDLE: u32 = 0x7e_0000;
const SC_SERIALIZABLE: u8 = 0x02;

const SEALED_OBJECT_FOR_KEY_PROTECTOR: &str = "com.sun.crypto.provider.SealedObjectForKeyProtector";
const SEALED_OBJECT: &str = "javax.crypto.SealedObject";
const SECRET_KEY_SPEC: &str = "javax.crypto.spec.SecretKeySpec";
// From the JDK's source: SealedObjectForKeyProtector.java,
// SealedObject.java and SecretKeySpec.java.
const UID_SEALED_OBJECT_FOR_KEY_PROTECTOR: i64 = -3650226485480866989;
const UID_SEALED_OBJECT: i64 = 4482838265551344752;
const UID_SECRET_KEY_SPEC: i64 = 6577238317307289933;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Primitive(Vec<u8>),
    String(String),
    Bytes(Vec<u8>),
    /// An object: its class name and its fields, superclass first.
    Object(String, Vec<(String, Value)>),
}

impl Value {
    pub fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Object(_, fields) => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct ClassDesc {
    name: String,
    fields: Vec<(u8, String)>,
    superclass: Option<Box<ClassDesc>>,
}

#[derive(Clone)]
enum Handle {
    Class(ClassDesc),
    Value(Value),
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    handles: Vec<Handle>,
    depth: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Result<&[u8], String> {
        let out = self.data.get(self.at..self.at + n).ok_or("Java serialization: truncated.")?;
        self.at += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().expect("two")))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().expect("four")))
    }

    fn utf(&mut self) -> Result<String, String> {
        let n = usize::from(self.u16()?);
        // Modified UTF-8 is UTF-8 for everything these names hold.
        Ok(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }

    fn handle(&self, index: u32) -> Result<&Handle, String> {
        index.checked_sub(BASE_HANDLE).and_then(|i| self.handles.get(i as usize))
            .ok_or_else(|| "Java serialization: a reference to nothing.".to_string())
    }

    fn class_desc(&mut self) -> Result<Option<ClassDesc>, String> {
        match self.u8()? {
            TC_NULL => Ok(None),
            TC_REFERENCE => {
                let index = self.u32()?;
                match self.handle(index)? {
                    Handle::Class(c) => Ok(Some(c.clone())),
                    Handle::Value(_) => Err("Java serialization: a reference to a value where \
                                             a class was expected.".to_string()),
                }
            }
            TC_CLASSDESC => {
                let name = self.utf()?;
                self.bytes(8)?; // serialVersionUID
                let slot = self.handles.len();
                self.handles.push(Handle::Class(ClassDesc { name: name.clone(), fields: Vec::new(),
                                                            superclass: None }));
                let flags = self.u8()?;
                if flags != SC_SERIALIZABLE {
                    return Err(format!("Java serialization: class {name} has flags {flags:#x}; \
                                        only plain Serializable is read here."));
                }
                let count = self.u16()?;
                let mut fields = Vec::new();
                for _ in 0..count {
                    let code = self.u8()?;
                    let field = self.utf()?;
                    if code == b'[' || code == b'L' {
                        self.content()?; // the field's class name
                    }
                    fields.push((code, field));
                }
                if self.u8()? != TC_ENDBLOCKDATA {
                    return Err("Java serialization: class annotations are not read here."
                        .to_string());
                }
                let superclass = self.class_desc()?.map(Box::new);
                let desc = ClassDesc { name, fields, superclass };
                self.handles[slot] = Handle::Class(desc.clone());
                Ok(Some(desc))
            }
            other => Err(format!("Java serialization: {other:#04x} where a class was expected.")),
        }
    }

    fn field_values(&mut self, desc: &ClassDesc, out: &mut Vec<(String, Value)>)
                    -> Result<(), String> {
        if let Some(superclass) = &desc.superclass {
            self.field_values(superclass, out)?;
        }
        for (code, name) in &desc.fields {
            let value = match code {
                b'B' | b'Z' => Value::Primitive(self.bytes(1)?.to_vec()),
                b'C' | b'S' => Value::Primitive(self.bytes(2)?.to_vec()),
                b'I' | b'F' => Value::Primitive(self.bytes(4)?.to_vec()),
                b'J' | b'D' => Value::Primitive(self.bytes(8)?.to_vec()),
                b'[' | b'L' => self.content()?,
                other => return Err(format!("Java serialization: field type {other}.")),
            };
            out.push((name.clone(), value));
        }
        Ok(())
    }

    fn content(&mut self) -> Result<Value, String> {
        self.depth += 1;
        if self.depth > 32 {
            return Err("Java serialization: nested more than 32 deep.".to_string());
        }
        let value = match self.u8()? {
            TC_NULL => Value::Null,
            TC_REFERENCE => {
                let index = self.u32()?;
                match self.handle(index)? {
                    Handle::Value(v) => v.clone(),
                    Handle::Class(_) => return Err("Java serialization: a reference to a class \
                                                    where a value was expected.".to_string()),
                }
            }
            TC_STRING => {
                let s = Value::String(self.utf()?);
                self.handles.push(Handle::Value(s.clone()));
                s
            }
            TC_ARRAY => {
                let desc = self.class_desc()?.ok_or("Java serialization: an array of no class.")?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(Value::Null));
                let n = self.u32()? as usize;
                if desc.name != "[B" {
                    return Err(format!("Java serialization: an array of {}; only byte arrays \
                                        are read here.", desc.name));
                }
                let v = Value::Bytes(self.bytes(n)?.to_vec());
                self.handles[slot] = Handle::Value(v.clone());
                v
            }
            TC_OBJECT => {
                let desc = self.class_desc()?.ok_or("Java serialization: an object of no class.")?;
                let slot = self.handles.len();
                self.handles.push(Handle::Value(Value::Null));
                let mut fields = Vec::new();
                self.field_values(&desc, &mut fields)?;
                let v = Value::Object(desc.name.clone(), fields);
                self.handles[slot] = Handle::Value(v.clone());
                v
            }
            other => return Err(format!("Java serialization: type code {other:#04x} is not \
                                         read here.")),
        };
        self.depth -= 1;
        Ok(value)
    }
}

/// Read one serialized object from the start of `data`; returns it and
/// how many bytes it took.
pub fn read(data: &[u8]) -> Result<(Value, usize), String> {
    if !data.starts_with(&MAGIC) {
        return Err("Not a Java serialization stream.".to_string());
    }
    let mut reader = Reader { data, at: 4, handles: Vec::new(), depth: 0 };
    let value = reader.content()?;
    Ok((value, reader.at))
}

// --------------------------------------------------------------- writing --

struct Writer {
    out: Vec<u8>,
    next: u32,
    strings: Vec<(String, u32)>,
}

impl Writer {
    fn utf(&mut self, s: &str) {
        self.out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        self.out.extend_from_slice(s.as_bytes());
    }

    fn handle(&mut self) -> u32 {
        self.next += 1;
        BASE_HANDLE + self.next - 1
    }

    /// A field's value: always a new string. `ObjectOutputStream` shares
    /// an object by identity, not by equality, and a sealed object's
    /// `paramsAlg` and `sealAlg` are two strings with the same text -
    /// Java writes both out, which a back-reference would not match.
    fn string(&mut self, s: &str) {
        self.out.push(TC_STRING);
        self.handle();
        self.utf(s);
    }

    /// A field's type in a class descriptor, or a back-reference to the
    /// same type written before: those are one object each in the JDK,
    /// so it shares them.
    fn type_string(&mut self, s: &str) {
        if let Some((_, h)) = self.strings.iter().find(|(t, _)| t == s) {
            let h = *h;
            self.out.push(TC_REFERENCE);
            self.out.extend_from_slice(&h.to_be_bytes());
            return;
        }
        self.out.push(TC_STRING);
        let h = self.handle();
        self.strings.push((s.to_string(), h));
        self.utf(s);
    }

    fn class(&mut self, name: &str, uid: i64, fields: &[(u8, &str, Option<&str>)],
             superclass: impl FnOnce(&mut Writer)) {
        self.out.push(TC_CLASSDESC);
        self.utf(name);
        self.out.extend_from_slice(&uid.to_be_bytes());
        self.handle();
        self.out.push(SC_SERIALIZABLE);
        self.out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for (code, field, class) in fields {
            self.out.push(*code);
            self.utf(field);
            if let Some(class) = class {
                self.type_string(class);
            }
        }
        self.out.push(TC_ENDBLOCKDATA);
        superclass(self);
    }

    fn bytes(&mut self, data: &[u8]) {
        self.out.push(TC_ARRAY);
        if let Some(h) = self.strings.iter().find(|(t, _)| t == "\0[B class").map(|(_, h)| *h) {
            self.out.push(TC_REFERENCE);
            self.out.extend_from_slice(&h.to_be_bytes());
        } else {
            self.out.push(TC_CLASSDESC);
            self.utf("[B");
            // byte[]'s serialVersionUID. No source declares it - the
            // runtime computes it - so it is held to the bytes keytool
            // wrote by `jks`'s `test_the_serialised_secret_key_is_javas`.
            self.out.extend_from_slice(&(-5984413125824719648i64).to_be_bytes());
            let h = self.handle();
            self.strings.push(("\0[B class".to_string(), h));
            self.out.extend_from_slice(&[SC_SERIALIZABLE, 0, 0, TC_ENDBLOCKDATA, TC_NULL]);
        }
        self.handle();
        self.out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.out.extend_from_slice(data);
    }
}

fn new_writer() -> Writer {
    Writer { out: MAGIC.to_vec(), next: 0, strings: Vec::new() }
}

/// A serialized `SecretKeySpec`: fields `algorithm` and `key`, in the
/// order the JDK sorts them.
pub fn secret_key_spec(algorithm: &str, key: &[u8]) -> Vec<u8> {
    let mut w = new_writer();
    w.out.push(TC_OBJECT);
    w.class(SECRET_KEY_SPEC, UID_SECRET_KEY_SPEC,
            &[(b'L', "algorithm", Some("Ljava/lang/String;")), (b'[', "key", Some("[B"))],
            |w| w.out.push(TC_NULL));
    w.handle();
    w.string(algorithm);
    w.bytes(key);
    w.out
}

/// A serialized `SealedObjectForKeyProtector` around an encrypted
/// object: its fields are `SealedObject`'s.
pub fn sealed_object(encoded_params: &[u8], encrypted: &[u8], params_alg: &str, seal_alg: &str)
                     -> Vec<u8> {
    let mut w = new_writer();
    w.out.push(TC_OBJECT);
    w.class(SEALED_OBJECT_FOR_KEY_PROTECTOR, UID_SEALED_OBJECT_FOR_KEY_PROTECTOR, &[], |w| {
        w.class(SEALED_OBJECT, UID_SEALED_OBJECT,
                &[(b'[', "encodedParams", Some("[B")), (b'[', "encryptedContent", Some("[B")),
                  (b'L', "paramsAlg", Some("Ljava/lang/String;")),
                  (b'L', "sealAlg", Some("Ljava/lang/String;"))],
                |w| w.out.push(TC_NULL));
    });
    w.handle();
    w.bytes(encoded_params);
    w.bytes(encrypted);
    w.string(params_alg);
    w.string(seal_alg);
    w.out
}

/// The parts of a sealed object: the encoded parameters, the
/// ciphertext, the parameter and sealing algorithm names.
pub fn unseal_parts(value: &Value) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let Value::Object(name, _) = value else {
        return Err("A JCEKS secret key entry that is not an object.".to_string());
    };
    if name != SEALED_OBJECT_FOR_KEY_PROTECTOR && name != SEALED_OBJECT {
        return Err(format!("A JCEKS secret key entry of class {name}."));
    }
    let bytes = |field: &str| match value.field(field) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(format!("The sealed object has no {field}.")),
    };
    let seal = match value.field("sealAlg") {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    Ok((bytes("encodedParams")?, bytes("encryptedContent")?, seal))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is written reads back, references and all.
    #[test]
    fn test_what_is_written_reads_back() {
        let spec = secret_key_spec("AES", &[7; 16]);
        let (value, used) = read(&spec).unwrap();
        assert_eq!(used, spec.len());
        assert_eq!(value.field("algorithm"), Some(&Value::String("AES".to_string())));
        assert_eq!(value.field("key"), Some(&Value::Bytes(vec![7; 16])));

        let sealed = sealed_object(&[1, 2, 3], &[4; 40], "PBEWithMD5AndTripleDES",
                                   "PBEWithMD5AndTripleDES");
        let mut with_more = sealed.clone();
        with_more.extend_from_slice(b"next entry");
        let (value, used) = read(&with_more).unwrap();
        assert_eq!(used, sealed.len());
        assert_eq!(unseal_parts(&value).unwrap(),
                   (vec![1, 2, 3], vec![4; 40], "PBEWithMD5AndTripleDES".to_string()));
    }
}

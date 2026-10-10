//! The files Kerberos keeps keys and tickets in - MIT's keytab and
//! credential cache formats, which Heimdal, Java and Windows tools write
//! too - and the tickets inside a cache.

use allcrypt::asn1::{tag, Reader, Tag, CLASS_APPLICATION};

/// The universal tag Kerberos strings carry (RFC 4120 5.2.1).
const GENERAL_STRING: u32 = 0x1b;

/// A principal: realm, name components and name type.
#[derive(Clone, Debug, PartialEq)]
pub struct Principal {
    pub realm: String,
    pub components: Vec<String>,
    pub name_type: u32,
}

impl Principal {
    /// `name/instance@REALM`, with `\` escapes for `/`, `@` and `\`.
    pub fn parse(text: &str, default_realm: Option<&str>) -> Result<Principal, String> {
        let mut components = vec![String::new()];
        let mut realm = None;
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            let in_realm = realm.is_some();
            let ch = match c {
                '\\' => chars.next().ok_or("A principal ending in \\.")?,
                '/' if !in_realm => {
                    components.push(String::new());
                    continue;
                }
                '@' if !in_realm => {
                    realm = Some(String::new());
                    continue;
                }
                other => other,
            };
            match realm.as_mut() {
                Some(r) => r.push(ch),
                None => components.last_mut().expect("never empty").push(ch),
            }
        }
        let realm = realm.or_else(|| default_realm.map(str::to_string))
            .ok_or_else(|| format!("{text}: no realm, and no default."))?;
        if components.iter().any(String::is_empty) || realm.is_empty() {
            return Err(format!("{text}: an empty name component or realm."));
        }
        // KRB5_NT_PRINCIPAL, which MIT's krb5_parse_name gives every name.
        Ok(Principal { realm, components, name_type: 1 })
    }

    /// The default salt: the realm and the components, concatenated.
    pub fn salt(&self) -> Vec<u8> {
        let mut out = self.realm.as_bytes().to_vec();
        for c in &self.components {
            out.extend_from_slice(c.as_bytes());
        }
        out
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let escape = |s: &str| s.replace('\\', "\\\\").replace('/', "\\/").replace('@', "\\@");
        let name: Vec<String> = self.components.iter().map(|c| escape(c)).collect();
        write!(f, "{}@{}", name.join("/"), escape(&self.realm))
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.data.len())
            .ok_or("The file ends early.")?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap_or([0; 2])))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap_or([0; 4])))
    }

    fn text(&mut self, len: usize) -> Result<String, String> {
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| "A name that is not UTF-8.".to_string())
    }

    fn done(&self) -> bool {
        self.at >= self.data.len()
    }
}

// --------------------------------------------------------------------- keytab --

#[derive(Clone, PartialEq)]
pub struct KeytabEntry {
    pub principal: Principal,
    pub timestamp: u32,
    pub kvno: u32,
    pub enctype: i32,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for KeytabEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeytabEntry").field("principal", &self.principal)
            .field("timestamp", &self.timestamp).field("kvno", &self.kvno)
            .field("enctype", &self.enctype)
            .field("key", &crate::hidden::HiddenBytes(&self.key)).finish()
    }
}

/// A keytab of version 0x0502, big endian, as every current
/// implementation writes it. Version 0x0501 - the writing machine's byte
/// order, no name types - is refused. Deleted entries, whose lengths are
/// negative, are skipped.
pub fn read_keytab(data: &[u8]) -> Result<Vec<KeytabEntry>, String> {
    let mut c = Cursor { data, at: 0 };
    if c.u8()? != 5 {
        return Err("Not a keytab.".to_string());
    }
    let version = c.u8()?;
    if version != 1 && version != 2 {
        return Err(format!("Keytab version 0x05{version:02x} is not one this reads."));
    }
    if version == 1 {
        return Err("Keytab version 0x0501, in the writing machine's byte order, is not read \
                    here.".to_string());
    }
    let mut entries = Vec::new();
    while !c.done() {
        let size = c.u32()? as i32;
        if size < 0 {
            c.take(size.unsigned_abs() as usize)?;
            continue;
        }
        if size == 0 {
            break;
        }
        let body = c.take(size as usize)?;
        let mut e = Cursor { data: body, at: 0 };
        let count = e.u16()?;
        let realm_len = e.u16()? as usize;
        let realm = e.text(realm_len)?;
        let mut components = Vec::new();
        for _ in 0..count {
            let len = e.u16()? as usize;
            components.push(e.text(len)?);
        }
        let name_type = e.u32()?;
        let timestamp = e.u32()?;
        let mut kvno = u32::from(e.u8()?);
        let enctype = i32::from(e.u16()? as i16);
        let key_len = e.u16()? as usize;
        let key = e.take(key_len)?.to_vec();
        // A 32-bit kvno after the key, when there is room, supersedes the
        // 8-bit one unless it is zero.
        if body.len() - e.at >= 4 {
            let wide = e.u32()?;
            if wide != 0 {
                kvno = wide;
            }
        }
        entries.push(KeytabEntry { principal: Principal { realm, components, name_type },
                                   timestamp, kvno, enctype, key });
    }
    Ok(entries)
}

pub fn write_keytab(entries: &[KeytabEntry]) -> Vec<u8> {
    let mut out = vec![5, 2];
    for entry in entries {
        let mut body = Vec::new();
        let p = &entry.principal;
        body.extend_from_slice(&(p.components.len() as u16).to_be_bytes());
        for text in std::iter::once(&p.realm).chain(&p.components) {
            body.extend_from_slice(&(text.len() as u16).to_be_bytes());
            body.extend_from_slice(text.as_bytes());
        }
        body.extend_from_slice(&p.name_type.to_be_bytes());
        body.extend_from_slice(&entry.timestamp.to_be_bytes());
        // The low byte, then the whole number after the key, as MIT writes
        // them.
        body.push(entry.kvno as u8);
        body.extend_from_slice(&(entry.enctype as u16).to_be_bytes());
        body.extend_from_slice(&(entry.key.len() as u16).to_be_bytes());
        body.extend_from_slice(&entry.key);
        body.extend_from_slice(&entry.kvno.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

// ---------------------------------------------------------------------- ccache --

#[derive(Clone)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub enctype: i32,
    pub session_key: Vec<u8>,
    pub authtime: u32,
    pub starttime: u32,
    pub endtime: u32,
    pub renew_till: u32,
    pub flags: u32,
    pub ticket: Vec<u8>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").field("client", &self.client)
            .field("server", &self.server).field("enctype", &self.enctype)
            .field("session_key", &crate::hidden::HiddenBytes(&self.session_key))
            .field("authtime", &self.authtime).field("starttime", &self.starttime)
            .field("endtime", &self.endtime).field("renew_till", &self.renew_till)
            .field("flags", &self.flags).field("ticket", &self.ticket).finish()
    }
}

pub struct Ccache {
    pub default_principal: Principal,
    pub credentials: Vec<Credential>,
}

fn ccache_principal(c: &mut Cursor) -> Result<Principal, String> {
    let name_type = c.u32()?;
    let count = c.u32()?;
    if count > 64 {
        return Err("A principal of more than 64 components.".to_string());
    }
    let realm_len = c.u32()? as usize;
    let realm = c.text(realm_len)?;
    let mut components = Vec::new();
    for _ in 0..count {
        let len = c.u32()? as usize;
        components.push(c.text(len)?);
    }
    Ok(Principal { realm, components, name_type })
}

/// A file credential cache, version 0x0503 or 0x0504 (big endian; the
/// fourth version has a header of tagged fields first, and the third
/// writes each session key's type twice). Configuration
/// entries - servers in the `X-CACHECONF:` realm - are skipped.
pub fn read_ccache(data: &[u8]) -> Result<Ccache, String> {
    let mut c = Cursor { data, at: 0 };
    if c.u8()? != 5 {
        return Err("Not a credential cache.".to_string());
    }
    let version = c.u8()?;
    if version != 3 && version != 4 {
        return Err(format!("Credential cache version 0x05{version:02x} is not one this \
                            reads."));
    }
    if version == 4 {
        let header_len = c.u16()? as usize;
        c.take(header_len)?;
    }
    let default_principal = ccache_principal(&mut c)?;
    let mut credentials = Vec::new();
    while !c.done() {
        let client = ccache_principal(&mut c)?;
        let server = ccache_principal(&mut c)?;
        let enctype = i32::from(c.u16()? as i16);
        // Version 3 writes the key's type twice.
        if version == 3 {
            c.u16()?;
        }
        let key_len = c.u32()? as usize;
        let session_key = c.take(key_len)?.to_vec();
        let (authtime, starttime, endtime, renew_till) = (c.u32()?, c.u32()?, c.u32()?, c.u32()?);
        let _is_skey = c.u8()?;
        let flags = c.u32()?;
        for _ in 0..c.u32()? {
            c.u16()?;
            let len = c.u32()? as usize;
            c.take(len)?;
        }
        for _ in 0..c.u32()? {
            c.u16()?;
            let len = c.u32()? as usize;
            c.take(len)?;
        }
        let ticket_len = c.u32()? as usize;
        let ticket = c.take(ticket_len)?.to_vec();
        let second_len = c.u32()? as usize;
        c.take(second_len)?;
        if server.realm == "X-CACHECONF:" {
            continue;
        }
        credentials.push(Credential { client, server, enctype, session_key, authtime,
                                      starttime, endtime, renew_till, flags, ticket });
    }
    Ok(Ccache { default_principal, credentials })
}

// --------------------------------------------------------------------- tickets --

/// `[n]` EXPLICIT, as Kerberos's ASN.1 tags every field.
fn field<'a>(r: &mut Reader<'a>, n: u32) -> Result<Reader<'a>, String> {
    Ok(Reader::new(r.read_tagged(Tag::context(n, true))?))
}

fn optional<'a>(r: &mut Reader<'a>, n: u32) -> Result<Option<Reader<'a>>, String> {
    Ok(r.read_optional_context(n, true)?.map(Reader::new))
}

fn kerberos_string(r: &mut Reader) -> Result<String, String> {
    let (t, content) = r.read_any()?;
    if t.class != 0 || t.number != GENERAL_STRING && t.number != tag::UTF8_STRING
        && t.number != tag::IA5_STRING {
        return Err("A Kerberos string of another type.".to_string());
    }
    String::from_utf8(content.to_vec()).map_err(|_| "A string that is not UTF-8.".to_string())
}

fn small_int(r: &mut Reader) -> Result<i64, String> {
    let bytes = r.read_tagged(Tag::universal(tag::INTEGER))?;
    if bytes.is_empty() || bytes.len() > 8 {
        return Err("An INTEGER out of range.".to_string());
    }
    let mut value = if bytes[0] & 0x80 != 0 { -1i64 } else { 0 };
    for b in bytes {
        value = (value << 8) | i64::from(*b);
    }
    Ok(value)
}

fn principal_name(r: &mut Reader, realm: &str) -> Result<Principal, String> {
    let mut seq = r.read_sequence()?;
    let name_type = small_int(&mut field(&mut seq, 0)?)? as u32;
    let mut strings = field(&mut seq, 1)?.read_sequence()?;
    let mut components = Vec::new();
    while !strings.is_empty() {
        components.push(kerberos_string(&mut strings)?);
    }
    Ok(Principal { realm: realm.to_string(), components, name_type })
}

/// A Ticket (RFC 4120 5.3): the service it is for and its encrypted part.
pub struct Ticket {
    pub server: Principal,
    pub enctype: i32,
    pub kvno: Option<u32>,
    pub cipher: Vec<u8>,
}

fn application<'a>(r: &mut Reader<'a>, n: u32) -> Result<Reader<'a>, String> {
    let wanted = Tag { class: CLASS_APPLICATION, constructed: true, number: n };
    Ok(Reader::new(r.read_tagged(wanted)?))
}

pub fn parse_ticket(der: &[u8]) -> Result<Ticket, String> {
    let mut outer = Reader::new(der);
    let mut app = application(&mut outer, 1)?;
    outer.finish()?;
    let mut seq = app.read_sequence()?;
    if small_int(&mut field(&mut seq, 0)?)? != 5 {
        return Err("A ticket of a version other than 5.".to_string());
    }
    let realm = kerberos_string(&mut field(&mut seq, 1)?)?;
    let server = principal_name(&mut field(&mut seq, 2)?, &realm)?;
    let mut enc = field(&mut seq, 3)?.read_sequence()?;
    let enctype = small_int(&mut field(&mut enc, 0)?)? as i32;
    let kvno = optional(&mut enc, 1)?.map(|mut r| small_int(&mut r)).transpose()?
        .map(|v| v as u32);
    let cipher = field(&mut enc, 2)?.read_octet_string()?.to_vec();
    Ok(Ticket { server, enctype, kvno, cipher })
}

/// What a ticket's encrypted part (EncTicketPart, RFC 4120 5.3) says.
pub struct TicketContents {
    pub flags: u32,
    pub enctype: i32,
    pub session_key: Vec<u8>,
    pub client: Principal,
    pub authtime: i64,
    pub starttime: Option<i64>,
    pub endtime: i64,
    pub renew_till: Option<i64>,
}

pub fn parse_enc_ticket_part(der: &[u8]) -> Result<TicketContents, String> {
    let mut outer = Reader::new(der);
    let mut app = application(&mut outer, 3)?;
    let mut seq = app.read_sequence()?;
    let flag_bits = field(&mut seq, 0)?.read_bit_string()?.to_vec();
    let mut flags = [0u8; 4];
    for (f, b) in flags.iter_mut().zip(&flag_bits) {
        *f = *b;
    }
    let mut key = field(&mut seq, 1)?.read_sequence()?;
    let enctype = small_int(&mut field(&mut key, 0)?)? as i32;
    let session_key = field(&mut key, 1)?.read_octet_string()?.to_vec();
    let crealm = kerberos_string(&mut field(&mut seq, 2)?)?;
    let client = principal_name(&mut field(&mut seq, 3)?, &crealm)?;
    field(&mut seq, 4)?; // transited
    let time = |r: Option<Reader>| r.map(|mut r| r.read_time()).transpose();
    let authtime = time(Some(field(&mut seq, 5)?))?.unwrap_or(0);
    let starttime = time(optional(&mut seq, 6)?)?;
    let endtime = time(Some(field(&mut seq, 7)?))?.unwrap_or(0);
    let renew_till = time(optional(&mut seq, 8)?)?;
    Ok(TicketContents { flags: u32::from_be_bytes(flags), enctype, session_key, client,
                        authtime, starttime, endtime, renew_till })
}

/// The flag names of RFC 4120 5.3, most significant bit first, with
/// anonymous (bit 14, RFC 6112) and enc-pa-rep (bit 15, RFC 6806).
pub fn flag_names(flags: u32) -> Vec<&'static str> {
    const NAMES: [&str; 16] = ["reserved", "forwardable", "forwarded", "proxiable", "proxy",
                               "may-postdate", "postdated", "invalid", "renewable", "initial",
                               "pre-authent", "hw-authent", "transited-policy-checked",
                               "ok-as-delegate", "anonymous", "enc-pa-rep"];
    NAMES.iter().enumerate().filter(|(i, _)| flags & (0x8000_0000 >> i) != 0)
        .map(|(_, n)| *n).collect()
}

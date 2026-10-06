//! Master files (RFC 1035 section 5): `$ORIGIN`, `$TTL`, owners carried
//! from the line before, parentheses across lines, comments, quoted
//! strings, and TTLs in BIND's units (`1h30m`).

use crate::name::Name;
use crate::rr::{self, Record, CLASS_IN};

/// Split a line into tokens: whitespace separates, `"..."` is one token
/// with its quotes kept, `;` starts a comment, and `(` and `)` are
/// tokens of their own.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            current.push(c);
            if c == '\\' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            ';' => break,
            '"' => {
                quoted = true;
                current.push(c);
            }
            '\\' => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '(' | ')' => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if quoted {
        return Err("A quoted string runs past the end of its line.".to_string());
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

/// `3600`, or BIND's `1w2d3h4m5s` in any combination.
pub fn parse_ttl(text: &str) -> Result<u32, String> {
    if let Ok(n) = text.parse::<u32>() {
        return Ok(n);
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800,
            _ => return Err(format!("{text}: not a TTL.")),
        };
        let n: u64 = digits.parse().map_err(|_| format!("{text}: not a TTL."))?;
        total += n * unit;
        digits.clear();
    }
    if !digits.is_empty() || total > u32::MAX as u64 {
        return Err(format!("{text}: not a TTL."));
    }
    Ok(total as u32)
}

fn is_ttl(token: &str) -> bool {
    token.starts_with(|c: char| c.is_ascii_digit()) && parse_ttl(token).is_ok()
}

fn class_of(token: &str) -> Option<u16> {
    let upper = token.to_ascii_uppercase();
    match upper.as_str() {
        "IN" => Some(CLASS_IN),
        "CH" => Some(3),
        "HS" => Some(4),
        _ => upper.strip_prefix("CLASS").and_then(|d| d.parse().ok()),
    }
}

/// Read a zone. `origin` is the starting `$ORIGIN`; the file's own
/// `$ORIGIN` lines change it as they come.
pub fn parse(text: &str, origin: &Name) -> Result<Vec<Record>, String> {
    let mut origin = origin.clone();
    let mut default_ttl: Option<u32> = None;
    let mut last_ttl: Option<u32> = None;
    let mut last_owner: Option<Name> = None;
    let mut records = Vec::new();

    let mut pending: Vec<String> = Vec::new();
    let mut pending_starts_blank = false;
    let mut depth = 0usize;
    let mut first_line = 0usize;

    for (number, line) in text.lines().enumerate() {
        let tokens = tokenize(line).map_err(|e| format!("line {}: {e}", number + 1))?;
        if depth == 0 {
            if tokens.is_empty() {
                continue;
            }
            pending_starts_blank = line.starts_with([' ', '\t']);
            first_line = number + 1;
        }
        for t in tokens {
            match t.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth = depth.checked_sub(1)
                        .ok_or_else(|| format!("line {}: a ) with no (.", number + 1))?;
                }
                _ => pending.push(t),
            }
        }
        if depth > 0 {
            continue;
        }
        let entry = std::mem::take(&mut pending);
        let at = |e: String| format!("line {first_line}: {e}");
        match entry[0].to_ascii_uppercase().as_str() {
            "$ORIGIN" => {
                let name = entry.get(1).ok_or_else(|| at("$ORIGIN needs a name.".into()))?;
                origin = Name::parse(name, Some(&origin)).map_err(at)?;
                continue;
            }
            "$TTL" => {
                let ttl = entry.get(1).ok_or_else(|| at("$TTL needs a value.".into()))?;
                default_ttl = Some(parse_ttl(ttl).map_err(at)?);
                continue;
            }
            d if d.starts_with('$') => return Err(at(format!("{d} is not supported."))),
            _ => {}
        }

        let mut fields = entry.as_slice();
        let owner = if pending_starts_blank {
            last_owner.clone().ok_or_else(|| at("A record with no owner.".into()))?
        } else {
            let owner = Name::parse(&fields[0], Some(&origin)).map_err(at)?;
            fields = &fields[1..];
            owner
        };
        let (mut ttl, mut class) = (None, None);
        for _ in 0..2 {
            match fields.first() {
                Some(t) if ttl.is_none() && is_ttl(t) => {
                    ttl = Some(parse_ttl(t).map_err(at)?);
                    fields = &fields[1..];
                }
                Some(t) if class.is_none() && rr::type_from_name(t).is_none()
                    && class_of(t).is_some() => {
                    class = class_of(t);
                    fields = &fields[1..];
                }
                _ => {}
            }
        }
        let type_token = fields.first().ok_or_else(|| at("A record with no type.".into()))?;
        let rtype = rr::type_from_name(type_token)
            .ok_or_else(|| at(format!("{type_token}: no such type.")))?;
        let rdata = rr::rdata_from_text(rtype, &fields[1..], &origin)
            .map_err(|e| at(format!("{}: {e}", rr::type_name(rtype))))?;
        let ttl = ttl.or(default_ttl).or(last_ttl)
            .ok_or_else(|| at("No TTL, and no $TTL before it.".into()))?;
        last_ttl = Some(ttl);
        last_owner = Some(owner.clone());
        records.push(Record { owner, ttl, class: class.unwrap_or(CLASS_IN), rtype, rdata });
    }
    if depth != 0 {
        return Err("The file ends inside parentheses.".to_string());
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_zone_with_every_shorthand() {
        let text = "$TTL 1h\n\
                    $ORIGIN example.\n\
                    @ IN SOA ns1 hostmaster ( 2024010101 ; serial\n\
                    \t 7200 3600 1209600 300 )\n\
                    \t NS ns1\n\
                    ns1 300 IN A 192.0.2.1\n\
                    \t IN 600 AAAA 2001:db8::1\n\
                    txt TXT \"a; not a comment\" two\n\
                    $ORIGIN sub.example.\n\
                    www CNAME @\n";
        let records = parse(text, &Name::root()).unwrap();
        let lines: Vec<String> = records.iter().map(Record::to_text).collect();
        assert_eq!(lines, [
            "example.\t3600\tIN\tSOA\tns1.example. hostmaster.example. 2024010101 7200 3600 1209600 300",
            "example.\t3600\tIN\tNS\tns1.example.",
            "ns1.example.\t300\tIN\tA\t192.0.2.1",
            "ns1.example.\t600\tIN\tAAAA\t2001:db8::1",
            "txt.example.\t3600\tIN\tTXT\t\"a; not a comment\" \"two\"",
            "www.sub.example.\t3600\tIN\tCNAME\tsub.example.",
        ]);
    }

    #[test]
    fn test_ttl_units() {
        assert_eq!(parse_ttl("1w2d3h4m5s").unwrap(), 604800 + 2 * 86400 + 3 * 3600 + 245);
        assert!(parse_ttl("5x").is_err());
    }

    #[test]
    fn test_errors_name_the_line() {
        let err = parse("$TTL 60\nexample. A 1.2.3\n", &Name::root()).unwrap_err();
        assert!(err.starts_with("line 2:"), "{err}");
        assert!(parse("example. 60 A ( 1.2.3.4\n", &Name::root()).is_err());
    }
}

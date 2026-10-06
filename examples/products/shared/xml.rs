//! XML read into a tree and written back, for the examples whose formats
//! carry some: a KeePass database's body, an Office document's
//! encryption descriptor.
//!
//! Enough of XML 1.0 for what those programs write: elements, attributes
//! in either quote, text, the five predefined entities and numeric
//! character references, CDATA sections, comments, processing
//! instructions (the declaration) and a byte-order mark. No DTDs - a
//! `<!DOCTYPE` is refused, which also refuses every entity-expansion
//! attack there is. Namespaces are not resolved: a prefixed name is kept
//! as written, `p:encryptedKey`, and `local_name` strips the prefix.

#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Node>,
}

impl Element {
    pub fn new(name: &str) -> Element {
        Element { name: name.to_string(), ..Element::default() }
    }

    /// The name without its namespace prefix.
    pub fn local_name(&self) -> &str {
        self.name.rsplit(':').next().unwrap_or(&self.name)
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    pub fn elements_mut(&mut self) -> impl Iterator<Item = &mut Element> {
        self.children.iter_mut().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|element| element.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |element| element.name == name)
    }

    /// The text content, concatenated.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for node in &self.children {
            if let Node::Text(text) = node {
                out.push_str(text);
            }
        }
        out
    }

    pub fn child_text(&self, name: &str) -> String {
        self.child(name).map(Element::text).unwrap_or_default()
    }

    // Building.

    pub fn with_attribute(mut self, name: &str, value: &str) -> Element {
        self.attributes.push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_text(mut self, text: &str) -> Element {
        self.children.push(Node::Text(text.to_string()));
        self
    }

    pub fn with_child(mut self, child: Element) -> Element {
        self.children.push(Node::Element(child));
        self
    }

    pub fn push(&mut self, child: Element) {
        self.children.push(Node::Element(child));
    }
}

// ----------------------------------------------------------------- read --

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
}

impl<'a> Reader<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn error<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("XML: {what} at byte {}", self.at))
    }

    fn skip_space(&mut self) {
        let trimmed = self.rest().trim_start_matches([' ', '\t', '\r', '\n']);
        self.at = self.text.len() - trimmed.len();
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.rest().starts_with(literal) {
            self.at += literal.len();
            true
        } else {
            false
        }
    }

    fn skip_past(&mut self, end: &str, what: &str) -> Result<&'a str, String> {
        match self.rest().find(end) {
            Some(offset) => {
                let skipped = &self.rest()[..offset];
                self.at += offset + end.len();
                Ok(skipped)
            }
            None => self.error(&format!("an unterminated {what}")),
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let length = self.rest().find(|c: char| !is_name_char(c)).unwrap_or(self.rest().len());
        if length == 0 {
            return self.error("a missing name");
        }
        let name = self.rest()[..length].to_string();
        self.at += length;
        Ok(name)
    }

    /// Comments, processing instructions and white space between
    /// elements.
    fn skip_misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_space();
            if self.eat("<!--") {
                self.skip_past("-->", "comment")?;
            } else if self.eat("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else if self.rest().starts_with("<!DOCTYPE") {
                return self.error("a document type declaration, which is not accepted");
            } else {
                return Ok(());
            }
        }
    }

    fn element(&mut self, depth: usize) -> Result<Element, String> {
        if depth > 256 {
            return self.error("elements nested more than 256 deep");
        }
        if !self.eat("<") {
            return self.error("an expected element");
        }
        let mut element = Element::new(&self.name()?);
        loop {
            self.skip_space();
            if self.eat("/>") {
                return Ok(element);
            }
            if self.eat(">") {
                break;
            }
            let name = self.name()?;
            self.skip_space();
            if !self.eat("=") {
                return self.error("an attribute without a value");
            }
            self.skip_space();
            let quote = match self.rest().chars().next() {
                Some(q @ ('"' | '\'')) => q,
                _ => return self.error("an unquoted attribute"),
            };
            self.at += 1;
            let raw = self.skip_past(&quote.to_string(), "attribute")?;
            element.attributes.push((name, unescape(raw).map_err(|e| format!("XML: {e}"))?));
        }
        let mut text = String::new();
        loop {
            if self.eat("</") {
                let name = self.name()?;
                if name != element.name {
                    return self.error(&format!("</{name}> closing <{}>", element.name));
                }
                self.skip_space();
                if !self.eat(">") {
                    return self.error("an unterminated end tag");
                }
                if !text.is_empty() {
                    element.children.push(Node::Text(text));
                }
                return Ok(element);
            } else if self.eat("<!--") {
                self.skip_past("-->", "comment")?;
            } else if self.eat("<![CDATA[") {
                text.push_str(self.skip_past("]]>", "CDATA section")?);
            } else if self.eat("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else if self.rest().starts_with('<') {
                if !text.is_empty() {
                    element.children.push(Node::Text(std::mem::take(&mut text)));
                }
                element.children.push(Node::Element(self.element(depth + 1)?));
            } else if self.rest().is_empty() {
                return self.error(&format!("<{}> not closed", element.name));
            } else {
                let length = self.rest().find('<').unwrap_or(self.rest().len());
                let raw = &self.rest()[..length];
                text.push_str(&unescape(raw).map_err(|e| format!("XML: {e}"))?);
                self.at += length;
            }
        }
    }
}

fn unescape(raw: &str) -> Result<String, String> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let end = rest[start..].find(';').ok_or("an unterminated entity")? + start;
        let name = &rest[start + 1..end];
        let c = match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = name.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(decimal) = name.strip_prefix('#') {
                    decimal.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32).ok_or(format!("an unknown entity &{name};"))?
            }
        };
        out.push(c);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The document's root element.
pub fn parse(bytes: &[u8]) -> Result<Element, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "XML: not UTF-8".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = Reader { text, at: 0 };
    reader.skip_misc()?;
    let root = reader.element(0)?;
    reader.skip_misc()?;
    if !reader.rest().is_empty() {
        return reader.error("content after the root element");
    }
    Ok(root)
}

// ---------------------------------------------------------------- write --

/// Escaped for text or for a double-quoted attribute. Characters XML 1.0
/// cannot carry at all - most control characters - are written as
/// nothing rather than as a document no parser accepts.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn write_element(element: &Element, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push('\t');
    }
    out.push('<');
    out.push_str(&element.name);
    for (name, value) in &element.attributes {
        out.push_str(&format!(" {}=\"{}\"", name, escape(value)));
    }
    if element.children.is_empty() {
        out.push_str(" />\n");
        return;
    }
    out.push('>');
    let only_text = element.children.iter().all(|node| matches!(node, Node::Text(_)));
    if only_text {
        out.push_str(&escape(&element.text()));
    } else {
        out.push('\n');
        for node in &element.children {
            match node {
                Node::Element(child) => write_element(child, depth + 1, out),
                Node::Text(text) => out.push_str(&escape(text)),
            }
        }
        for _ in 0..depth {
            out.push('\t');
        }
    }
    out.push_str(&format!("</{}>\n", element.name));
}

pub fn write(root: &Element) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n");
    write_element(root, 0, &mut out);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_document_reads_with_entities_cdata_and_comments() {
        let doc = "\u{feff}<?xml version=\"1.0\"?>\n<!-- c --><a x='1 &amp; 2' y=\"&#x41;\">\
                   <b>t &lt;&#169;&gt;</b><!-- inside --><c/><b><![CDATA[<raw>&]]></b></a>\n";
        let root = parse(doc.as_bytes()).unwrap();
        assert_eq!(root.attribute("x"), Some("1 & 2"));
        assert_eq!(root.attribute("y"), Some("A"));
        let texts: Vec<String> = root.children_named("b").map(Element::text).collect();
        assert_eq!(texts, ["t <\u{a9}>", "<raw>&"]);
        assert!(root.child("c").unwrap().children.is_empty());
    }

    #[test]
    fn test_what_is_written_reads_back() {
        let tricky = "<&>\"' \u{2603}\n\ttab";
        let root = Element::new("r").with_attribute("k", tricky)
            .with_child(Element::new("v").with_text(tricky))
            .with_child(Element::new("empty"));
        let back = parse(&write(&root)).unwrap();
        assert_eq!(back.attribute("k"), Some(tricky));
        assert_eq!(back.child_text("v"), tricky);
        assert!(back.child("empty").is_some());
    }

    #[test]
    fn test_malformed_documents_are_refused() {
        for doc in ["<a>", "<a></b>", "<a x=1/>", "<a>&nope;</a>", "<a/><b/>",
                    "<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>", "<a>&#xD800;</a>"] {
            assert!(parse(doc.as_bytes()).is_err(), "{doc}");
        }
    }
}

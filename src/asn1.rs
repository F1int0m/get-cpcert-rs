//! Minimal BER/DER parser sufficient to walk CryptoPro container files.
//!
//! Supports:
//!  * definite-length encoding (BER/DER)
//!  * indefinite-length encoding for constructed types (terminated by 0x00 0x00)
//!  * multi-byte tag numbers (long-form identifier)
//!
//! This is intentionally small and tailored to our needs — not a general ASN.1
//! library.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

impl TagClass {
    fn from_bits(b: u8) -> Self {
        match (b >> 6) & 0b11 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            3 => TagClass::Private,
            _ => unreachable!(),
        }
    }
}

/// Universal ASN.1 tag numbers we care about.
pub mod universal {
    pub const INTEGER: u32 = 0x02;
    pub const OCTET_STRING: u32 = 0x04;
    pub const NULL: u32 = 0x05;
    pub const OID: u32 = 0x06;
    pub const SEQUENCE: u32 = 0x10;
    pub const SET: u32 = 0x11;
}

#[derive(Debug, Clone)]
pub struct Node {
    pub class: TagClass,
    pub tag: u32,
    pub constructed: bool,
    /// Raw content bytes (for primitive types) or the concatenated
    /// content of children (for constructed types — kept for convenience).
    pub content: Vec<u8>,
    pub children: Vec<Node>,
}

impl Node {
    /// Returns true if this node is the universal `OBJECT IDENTIFIER` type.
    pub fn is_oid(&self) -> bool {
        self.class == TagClass::Universal && self.tag == universal::OID && !self.constructed
    }

    /// Returns true if this is a primitive OCTET STRING.
    pub fn is_octet_string(&self) -> bool {
        self.class == TagClass::Universal
            && self.tag == universal::OCTET_STRING
            && !self.constructed
    }

    /// Decode an OID node into dot-notation. Returns Err if not an OID.
    pub fn as_oid_string(&self) -> Result<String> {
        if !self.is_oid() {
            return Err(Error::Asn1("not an OID node".into()));
        }
        decode_oid(&self.content)
    }

    /// Walk children recursively and collect references to all OID nodes.
    pub fn collect_oids<'a>(&'a self, out: &mut Vec<&'a Node>) {
        if self.is_oid() {
            out.push(self);
        }
        for c in &self.children {
            c.collect_oids(out);
        }
    }

    /// Walk children recursively and collect (path, node) for every
    /// context-specific tag.  Path is the chain of indices from the root.
    pub fn collect_context<'a>(&'a self, prefix: &[usize], out: &mut Vec<(Vec<usize>, &'a Node)>) {
        if self.class == TagClass::ContextSpecific {
            out.push((prefix.to_vec(), self));
        }
        for (i, c) in self.children.iter().enumerate() {
            let mut p = prefix.to_vec();
            p.push(i);
            c.collect_context(&p, out);
        }
    }
}

/// Decode an OID's content bytes into dot-string notation.
fn decode_oid(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Err(Error::Asn1("empty OID".into()));
    }
    let mut out = String::new();
    let first = bytes[0];
    out.push_str(&format!("{}.{}", first / 40, first % 40));

    let mut i = 1usize;
    while i < bytes.len() {
        let mut v: u64 = 0;
        loop {
            if i >= bytes.len() {
                return Err(Error::Asn1("truncated OID".into()));
            }
            let b = bytes[i];
            i += 1;
            v = (v << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push('.');
        out.push_str(&v.to_string());
    }
    Ok(out)
}

/// A small cursor over a byte slice with bounds-checked reads.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek(&self, off: usize) -> Result<u8> {
        self.data
            .get(self.pos + off)
            .copied()
            .ok_or_else(|| Error::Asn1("unexpected EOF".into()))
    }

    fn read_u8(&mut self) -> Result<u8> {
        let b = self.peek(0)?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Asn1("short read".into()));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Parse a single TLV at the cursor's current position. May recurse for
/// constructed types.
fn parse_one(cur: &mut Cursor<'_>) -> Result<Node> {
    let id = cur.read_u8()?;
    let class = TagClass::from_bits(id);
    let constructed = (id & 0x20) != 0;

    let mut tag = u32::from(id & 0x1f);
    if tag == 0x1f {
        // long-form tag number
        tag = 0;
        loop {
            let b = cur.read_u8()?;
            tag = (tag << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    // Length
    let first_len = cur.read_u8()?;
    let (content, children, _used_indef) = if first_len == 0x80 {
        // Indefinite — only valid for constructed.
        if !constructed {
            return Err(Error::Asn1("indefinite length on primitive type".into()));
        }
        let mut kids = Vec::new();
        let mut collected = Vec::new();
        loop {
            // EOC = 0x00 0x00
            if cur.remaining() >= 2 && cur.peek(0)? == 0x00 && cur.peek(1)? == 0x00 {
                cur.pos += 2;
                break;
            }
            let child = parse_one(cur)?;
            collected.extend_from_slice(&child.content);
            kids.push(child);
        }
        (collected, kids, true)
    } else {
        let len = if first_len & 0x80 == 0 {
            usize::from(first_len)
        } else {
            let nbytes = usize::from(first_len & 0x7f);
            if nbytes == 0 || nbytes > 8 {
                return Err(Error::Asn1("bad length encoding".into()));
            }
            let mut len: usize = 0;
            for _ in 0..nbytes {
                len = (len << 8) | usize::from(cur.read_u8()?);
            }
            len
        };

        let raw = cur.read_slice(len)?.to_vec();
        let kids = if constructed {
            let mut sub = Cursor::new(&raw[..]);
            // Local owned cursor — re-parse children into owned nodes.
            let mut v = Vec::new();
            while sub.remaining() > 0 {
                v.push(parse_one_owned(&mut sub)?);
            }
            v
        } else {
            Vec::new()
        };
        (raw, kids, false)
    };

    Ok(Node {
        class,
        tag,
        constructed,
        content,
        children,
    })
}

/// Like parse_one but works on an owned cursor (used to recurse into
/// already-read content of constructed nodes).
fn parse_one_owned(cur: &mut Cursor<'_>) -> Result<Node> {
    parse_one(cur)
}

/// Parse the *first* ASN.1 element from `data` (typical case for the
/// container files — one root SEQUENCE).
pub fn parse(data: &[u8]) -> Result<Node> {
    let mut cur = Cursor::new(data);
    parse_one(&mut cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_integer() {
        // INTEGER 0x12345678
        let data = [0x02, 0x04, 0x12, 0x34, 0x56, 0x78];
        let n = parse(&data).unwrap();
        assert_eq!(n.class, TagClass::Universal);
        assert_eq!(n.tag, universal::INTEGER);
        assert!(!n.constructed);
        assert_eq!(n.content, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn parse_long_length() {
        // OCTET STRING with 130 bytes — uses 2-byte length form 0x82 0x00 0x82
        let mut data = vec![0x04, 0x81, 130];
        data.extend(std::iter::repeat(0xAB).take(130));
        let n = parse(&data).unwrap();
        assert_eq!(n.content.len(), 130);
    }

    #[test]
    fn parse_sequence_with_children() {
        // SEQUENCE { INTEGER 1, OCTET STRING "AB" }
        let data = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'A', b'B'];
        let n = parse(&data).unwrap();
        assert!(n.constructed);
        assert_eq!(n.tag, universal::SEQUENCE);
        assert_eq!(n.children.len(), 2);
        assert_eq!(n.children[0].content, vec![1]);
        assert_eq!(n.children[1].content, b"AB");
    }

    #[test]
    fn parse_indefinite_length() {
        // SEQUENCE indefinite { INTEGER 5 } EOC
        let data = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
        let n = parse(&data).unwrap();
        assert!(n.constructed);
        assert_eq!(n.children.len(), 1);
        assert_eq!(n.children[0].content, vec![5]);
    }

    #[test]
    fn decode_well_known_oid() {
        // OID 1.2.643.7.1.1.2.2  (GOST R 34.11-2012 with 256-bit hash)
        // BER encoding: 06 08 2A 85 03 07 01 01 02 02
        let data = [0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02];
        let n = parse(&data).unwrap();
        assert!(n.is_oid());
        assert_eq!(n.as_oid_string().unwrap(), "1.2.643.7.1.1.2.2");
    }

    #[test]
    fn decode_short_oid() {
        // 1.2.840.10045.2.1  (id-ecPublicKey, just to sanity-check the parser)
        let data = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let n = parse(&data).unwrap();
        assert_eq!(n.as_oid_string().unwrap(), "1.2.840.10045.2.1");
    }

    #[test]
    fn truncated_input_errors_cleanly() {
        // Length says 10 bytes, only 3 available.
        let data = [0x04, 0x0A, 0x01, 0x02, 0x03];
        assert!(parse(&data).is_err());
    }

    #[test]
    fn context_specific_primitive_tag_recognized() {
        // [10] IMPLICIT OCTET STRING (primitive, 8 bytes) — matches the
        // pub8 field shape inside header.key.
        //  0x8A = context-specific (10) primitive, tag 10
        let data = [0x8A, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        let n = parse(&data).unwrap();
        assert_eq!(n.class, TagClass::ContextSpecific);
        assert_eq!(n.tag, 10);
        assert!(!n.constructed);
        assert_eq!(n.content, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}

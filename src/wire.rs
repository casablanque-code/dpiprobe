//! Wire-level helpers: a hand-built TLS ClientHello and a tolerant parser for it.

/// A TLS ChangeCipherSpec record. Used as a cheap, harmless "padding packet"
/// that the server knows to skip in front of a ClientHello.
pub const CCS: [u8; 6] = [0x14, 3, 3, 0, 1, 1];

/// TLS alert record: fatal handshake_failure. The server's one-shot reply.
pub const ALERT: [u8; 7] = [0x15, 3, 3, 0, 2, 2, 40];

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Build a minimal TLS 1.3-flavoured ClientHello. The 32-byte `random` field
/// doubles as a correlation token between probe and server.
///
/// `sni_last` moves the server_name extension to the end of the extension list;
/// `pad_ext` prepends a padding extension of that many zero bytes, which pushes
/// the hostname deeper into the packet.
pub fn build_client_hello(sni: &str, random: &[u8; 32], sni_last: bool, pad_ext: usize) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sn = Vec::new();
    sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sn.push(0);
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);
    let mut sni_ext = vec![0, 0];
    sni_ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sn);

    let mut ext = Vec::new();
    if pad_ext > 0 {
        ext.extend_from_slice(&[0, 0x15]);
        ext.extend_from_slice(&(pad_ext as u16).to_be_bytes());
        ext.extend(std::iter::repeat(0u8).take(pad_ext));
    }
    if !sni_last {
        ext.extend_from_slice(&sni_ext);
    }
    ext.extend_from_slice(&[0, 0x0a, 0, 4, 0, 2, 0, 0x1d]); // supported_groups: x25519
    ext.extend_from_slice(&[0, 0x0d, 0, 4, 0, 2, 8, 4]); // signature_algorithms
    ext.extend_from_slice(&[0, 0x2b, 0, 3, 2, 3, 4]); // supported_versions: TLS 1.3
    if sni_last {
        ext.extend_from_slice(&sni_ext);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(0); // empty session id
    body.extend_from_slice(&[0, 6, 0x13, 1, 0x13, 2, 0xc0, 0x2f]); // cipher suites
    body.extend_from_slice(&[1, 0]); // compression: null
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Offset of the SNI hostname inside the ClientHello bytes.
pub fn sni_offset(ch: &[u8], sni: &str) -> Option<usize> {
    let name = sni.as_bytes();
    if name.is_empty() {
        return None;
    }
    ch.windows(name.len()).position(|w| w == name)
}

/// Strip leading padding records (see `CCS`).
pub fn skip_pad(mut b: &[u8]) -> &[u8] {
    while b.starts_with(&CCS) {
        b = &b[CCS.len()..];
    }
    b
}

pub struct Hello {
    /// Hex of the ClientHello random: the correlation token.
    pub id: String,
    /// SNI, if the extension was fully received.
    pub sni: Option<String>,
}

/// Parse as much of a ClientHello as has arrived. Returns None until the
/// fixed header (up to and including the random) is present.
pub fn parse_client_hello(b: &[u8]) -> Option<Hello> {
    if b.len() < 44 || b[0] != 0x16 || b[5] != 1 {
        return None;
    }
    let id = hex(&b[11..43]);
    let mut p = 43;
    p += 1 + *b.get(p)? as usize;
    p += 2 + u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 1 + *b.get(p)? as usize;
    let el = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + el).min(b.len());
    let mut sni = None;
    while p + 4 <= end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if t == 0 && l >= 5 && p + 4 + l <= end {
            let d = &b[p + 4..p + 4 + l];
            let nl = u16::from_be_bytes([d[3], d[4]]) as usize;
            if let Some(n) = d.get(5..5 + nl) {
                sni = Some(String::from_utf8_lossy(n).to_string());
            }
        }
        p += 4 + l;
    }
    Some(Hello { id, sni })
}

/// True once the whole TLS record holding the ClientHello has arrived.
pub fn ch_complete(b: &[u8]) -> bool {
    b.len() >= 5 && b.len() >= 5 + u16::from_be_bytes([b[3], b[4]]) as usize
}

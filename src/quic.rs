//! QUIC v1 Initial packets (RFC 9000/9001): build the client Initial that carries
//! a TLS ClientHello with an SNI, and decrypt one on the server side.
//!
//! Initial packets are protected with keys derived from the destination connection
//! ID, which is public: anyone on the path (including a middlebox) can decrypt them.
//! That is exactly what makes SNI-based QUIC filtering possible.

use crate::wire::{build_client_hello, hex, parse_client_hello, Hello};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{generic_array::GenericArray, Aead, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// Marker the server puts in replies to non-QUIC UDP probes.
pub const UDP_ECHO: &[u8] = b"dpiprobe-echo";

pub struct Keys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

fn expand_label(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {}", label);
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hk.expand(&info, out).expect("hkdf expand");
}

/// Client Initial keys for a given destination connection ID.
pub fn client_initial_keys(dcid: &[u8]) -> Keys {
    let (_, initial) = Hkdf::<Sha256>::extract(Some(&SALT_V1), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, "client in", &mut secret);
    let hk = Hkdf::<Sha256>::from_prk(&secret).expect("prk");
    let mut k = Keys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
    expand_label(&hk, "quic key", &mut k.key);
    expand_label(&hk, "quic iv", &mut k.iv);
    expand_label(&hk, "quic hp", &mut k.hp);
    k
}

fn hp_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp));
    let mut block = GenericArray::clone_from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

fn put_varint(v: &mut Vec<u8>, x: usize) {
    if x < 64 {
        v.push(x as u8);
    } else if x < 16384 {
        v.extend_from_slice(&((x as u16) | 0x4000).to_be_bytes());
    } else {
        v.extend_from_slice(&((x as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn get_varint(b: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as usize;
    for i in 1..len {
        v = (v << 8) | *b.get(*pos + i)? as usize;
    }
    *pos += len;
    Some(v)
}

/// Build a client Initial datagram (padded to 1200 bytes) carrying a ClientHello
/// for `sni`. The ClientHello random doubles as the correlation token.
pub fn build_initial(sni: &str, random: &[u8; 32], dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let rec = build_client_hello(sni, random, false, 0);
    let ch = &rec[5..]; // the handshake message, without the TLS record header

    let mut payload = vec![0x06]; // CRYPTO frame
    put_varint(&mut payload, 0);
    put_varint(&mut payload, ch.len());
    payload.extend_from_slice(ch);

    const PN_LEN: usize = 4;
    let mut header = vec![0xc0 | (PN_LEN as u8 - 1), 0, 0, 0, 1];
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    header.push(0); // token length

    // Pad the payload so that the whole datagram reaches 1200 bytes.
    let fixed = header.len() + 2 + PN_LEN + 16;
    if fixed + payload.len() < 1200 {
        payload.resize(1200 - fixed, 0);
    }
    let length = PN_LEN + payload.len() + 16;
    header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(&[0, 0, 0, 0]); // packet number 0

    let keys = client_initial_keys(dcid);
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let ct = cipher
        .encrypt(GenericArray::from_slice(&nonce(&keys.iv, 0)), Payload { msg: &payload, aad: &header })
        .expect("encrypt");

    let mut pkt = header;
    pkt.extend_from_slice(&ct);
    let mask = hp_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 20]);
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..PN_LEN {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

pub struct Initial {
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// Reassembled CRYPTO data: the TLS handshake message (ClientHello).
    pub crypto: Vec<u8>,
}

/// Decrypt a client Initial datagram.
pub fn parse_initial(dg: &[u8]) -> Option<Initial> {
    if dg.len() < 21 || dg[0] & 0x80 == 0 || (dg[0] >> 4) & 3 != 0 || dg[1..5] != [0, 0, 0, 1] {
        return None;
    }
    let mut pos = 5;
    let dl = *dg.get(pos)? as usize;
    let dcid = dg.get(pos + 1..pos + 1 + dl)?.to_vec();
    pos += 1 + dl;
    let sl = *dg.get(pos)? as usize;
    let scid = dg.get(pos + 1..pos + 1 + sl)?.to_vec();
    pos += 1 + sl;
    let token = get_varint(dg, &mut pos)?;
    pos += token;
    let length = get_varint(dg, &mut pos)?;
    let pn_offset = pos;
    let end = pn_offset.checked_add(length)?;
    if end > dg.len() || length < 4 + 16 {
        return None;
    }

    let keys = client_initial_keys(&dcid);
    let mask = hp_mask(&keys.hp, dg.get(pn_offset + 4..pn_offset + 20)?);
    let first = dg[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 3) as usize + 1;
    let mut header = dg[..pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let plain = cipher
        .decrypt(GenericArray::from_slice(&nonce(&keys.iv, pn)), Payload { msg: &dg[pn_offset + pn_len..end], aad: &header })
        .ok()?;

    // Walk the frames; keep CRYPTO data (assumes it arrives in order from offset 0).
    let mut crypto = Vec::new();
    let mut p = 0;
    while p < plain.len() {
        match plain[p] {
            0x00 | 0x01 => p += 1, // PADDING, PING
            0x06 => {
                p += 1;
                let off = get_varint(&plain, &mut p)?;
                let len = get_varint(&plain, &mut p)?;
                let data = plain.get(p..p + len)?;
                if off == crypto.len() {
                    crypto.extend_from_slice(data);
                }
                p += len;
            }
            _ => break,
        }
    }
    Some(Initial { dcid, scid, crypto })
}

/// ClientHello inside an Initial, parsed with the TLS-record helper from `wire`.
pub fn hello_of(init: &Initial) -> Option<Hello> {
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(init.crypto.len() as u16).to_be_bytes());
    rec.extend_from_slice(&init.crypto);
    parse_client_hello(&rec)
}

/// A Version Negotiation packet: the cheapest valid reply a QUIC server can send.
pub fn version_negotiation(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut v = vec![0x8a, 0, 0, 0, 0];
    v.push(scid.len() as u8); // our DCID is the client's SCID
    v.extend_from_slice(scid);
    v.push(dcid.len() as u8);
    v.extend_from_slice(dcid);
    v.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes()); // a reserved "grease" version
    v
}

/// A QUIC-looking reply? (long header with version 0 = Version Negotiation)
pub fn is_version_negotiation(b: &[u8]) -> bool {
    b.len() >= 7 && b[0] & 0x80 != 0 && b[1..5] == [0, 0, 0, 0]
}

/// Fixed identifiers used by `dpiprobe initial`, so fixtures are reproducible.
pub fn fixture_initial(sni: &str) -> Vec<u8> {
    build_initial(sni, &[0x11; 32], &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08], &[0xaa, 0xbb, 0xcc, 0xdd])
}

#[allow(dead_code)]
pub fn token_of(init: &Initial) -> Option<String> {
    hello_of(init).map(|h| h.id)
}

#[allow(dead_code)]
pub fn dump_hex(b: &[u8]) -> String {
    hex(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001, Appendix A.1: keys for DCID 0x8394c8f03e515708.
    #[test]
    fn rfc9001_client_initial_keys() {
        let k = client_initial_keys(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        assert_eq!(hex(&k.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&k.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&k.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    // RFC 9001, Appendix A.2: header protection of the first client Initial.
    #[test]
    fn rfc9001_header_protection_mask() {
        let k = client_initial_keys(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let sample: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&"d1b1c98dd7689fb8ec11d242b123dc9b"[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert_eq!(hex(&hp_mask(&k.hp, &sample)[..5]), "437b9aec36");
    }

    #[test]
    fn build_then_parse_roundtrip() {
        let dg = build_initial("blocked.example", &[7u8; 32], &[1, 2, 3, 4, 5, 6, 7, 8], &[9, 9]);
        assert_eq!(dg.len(), 1200);
        let init = parse_initial(&dg).expect("decrypts");
        assert_eq!(init.scid, vec![9, 9]);
        let h = hello_of(&init).expect("hello");
        assert_eq!(h.sni.as_deref(), Some("blocked.example"));
        assert_eq!(h.id, hex(&[7u8; 32]));
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_initial(&[0x40; 64]).is_none());
        let mut dg = fixture_initial("x.example");
        let n = dg.len();
        dg[n - 1] ^= 1; // corrupt the AEAD tag
        assert!(parse_initial(&dg).is_none());
    }
}

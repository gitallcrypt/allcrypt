//! IEEE 802.11's KDF over SHA-256, SHA-384 and SHA-512, Suite B 192-bit's
//! PTK and the fast BSS transition key hierarchy, against hostapd
//! (wpa_supplicant 2.11) and Wireshark 4.6's dot11decrypt:
//! `vectors/ieee80211_ft.vec`, written by
//! `scripts/make_ieee80211_ft_vectors.py`.

use std::collections::HashMap;

use allcrypt::api;

fn hex(v: &str) -> Vec<u8> {
    if v == "-" {
        return Vec::new();
    }
    (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap()).collect()
}

fn rows() -> Vec<(String, HashMap<String, String>)> {
    include_str!("../vectors/ieee80211_ft.vec").lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap().to_string();
            (kind, parts.map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            }).collect())
        })
        .collect()
}

#[test]
fn test_the_witnesses_rows() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut both = 0;
    for (kind, f) in rows() {
        let h = |k: &str| hex(&f[k]);
        let (out, name) = match kind.as_str() {
            "kdf" => (api::ieee80211_kdf(&format!("sha{}", f["hash"]), &h("key"), &h("label"),
                                         &h("context"), f["bytes"].parse::<usize>().unwrap() * 8)
                          .unwrap(), None),
            "ptk384" => (api::wpa_ptk("sha384", &h("pmk"), &h("aa"), &h("spa"), &h("anonce"),
                                      &h("snonce"), (24 + 32 + 32) * 8).unwrap(), None),
            "r0" => {
                let (key, name) = api::wpa_ft_pmk_r0(&h("xxkey"), &h("ssid"), &h("mdid"),
                                                     &h("r0kh"), &h("s0kh")).unwrap();
                (key, Some(name))
            }
            "r1" => {
                let (key, name) = api::wpa_ft_pmk_r1(&h("pmk_r0"), &h("pmk_r0_name"), &h("r1kh"),
                                                     &h("s1kh")).unwrap();
                (key, Some(name))
            }
            "ftptk" => {
                let pmk_r1 = h("pmk_r1");
                let (kck, kek) = match pmk_r1.len() {
                    32 => (16, 16),
                    48 => (24, 32),
                    _ => (32, 32),
                };
                let tk = if f["cipher"] == "ccmp" { 16 } else { 32 };
                (api::wpa_ft_ptk(&pmk_r1, &h("snonce"), &h("anonce"), &h("bssid"), &h("sta"),
                                 (kck + kek + tk) * 8).unwrap(), None)
            }
            other => panic!("unknown row kind {other}"),
        };
        assert_eq!(out, h("out"), "{kind} {f:?}");
        if let Some(name) = name {
            assert_eq!(name, h("name"), "{kind} name {f:?}");
        }
        both += usize::from(f["witnesses"] == "hostapd,wireshark");
        *counts.entry(kind).or_default() += 1;
    }
    assert_eq!(counts["kdf"], 480);
    assert_eq!(counts["ptk384"], 60);
    assert_eq!(counts["r0"], 240);
    assert_eq!(counts["r1"], 120);
    assert_eq!(counts["ftptk"], 120);
    assert!(both >= 600, "{both} rows with both witnesses");
}

/// What the derivations refuse: keys of no hash's length, an SSID or an
/// R0KH-ID out of range, and fields of the wrong size.
#[test]
fn test_what_is_refused() {
    let (s, m, a) = (b"ssid".as_slice(), [1u8, 2], [9u8; 6]);
    for len in [0, 16, 31, 33, 47, 49, 63, 65] {
        assert!(api::wpa_ft_pmk_r0(&vec![0; len], s, &m, b"r0", &a).is_err(), "XXKey {len}");
        assert!(api::wpa_ft_pmk_r1(&vec![0; len], &[0; 16], &a, &a).is_err(), "PMK-R0 {len}");
        assert!(api::wpa_ft_ptk(&vec![0; len], &[0; 32], &[0; 32], &a, &a, 384).is_err());
    }
    assert!(api::wpa_ft_pmk_r0(&[0; 32], &[0; 32], &m, b"r0", &a).is_ok());
    assert!(api::wpa_ft_pmk_r0(&[0; 32], &[0; 33], &m, b"r0", &a).is_err(), "SSID 33");
    assert!(api::wpa_ft_pmk_r0(&[0; 32], s, &m, &[7; 48], &a).is_ok());
    assert!(api::wpa_ft_pmk_r0(&[0; 32], s, &m, &[7; 49], &a).is_err(), "R0KH-ID 49");
    assert!(api::wpa_ft_pmk_r0(&[0; 32], s, &m, b"", &a).is_err(), "empty R0KH-ID");
    assert!(api::wpa_ft_pmk_r0(&[0; 32], s, &[1], b"r0", &a).is_err(), "MDID 1");
    assert!(api::wpa_ft_pmk_r1(&[0; 32], &[0; 15], &a, &a).is_err(), "name 15");
    assert!(api::wpa_ft_ptk(&[0; 32], &[0; 31], &[0; 32], &a, &a, 384).is_err(), "nonce 31");
    assert!(api::ieee80211_kdf("sha1", b"k", b"l", b"c", 256).is_err());
    assert!(api::wpa_ptk("sha512", &[0; 64], &a, &a, &[0; 32], &[0; 32], 256).is_err());
}

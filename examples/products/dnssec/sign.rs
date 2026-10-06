//! Signing a zone and checking one: RRSIGs over every authoritative
//! RRset (RFC 4034 section 3, RFC 4035 section 2), and denial of
//! existence by an NSEC chain (RFC 4034 section 4) or an NSEC3 chain
//! (RFC 5155 section 7.1).

use std::collections::{BTreeMap, BTreeSet};

use crate::keys::{self, Key};
use crate::name::Name;
use crate::rr::{self, Dnskey, Nsec3, Nsec3Param, Record, Rrsig};

/// A name in canonical order, for maps and sets.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Owner(Name);

impl PartialOrd for Owner {
    fn partial_cmp(&self, other: &Owner) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Owner {
    fn cmp(&self, other: &Owner) -> std::cmp::Ordering {
        self.0.canonical_cmp(&other.0)
    }
}

/// The zone's RRsets, grouped by owner then type.
struct Zone {
    apex: Name,
    sets: BTreeMap<Owner, BTreeMap<u16, Vec<Record>>>,
}

impl Zone {
    fn new(records: Vec<Record>) -> Result<Zone, String> {
        let apex = records.iter().find(|r| r.rtype == rr::SOA).map(|r| r.owner.clone())
            .ok_or("The zone has no SOA record.")?;
        if records.iter().filter(|r| r.rtype == rr::SOA).count() != 1 {
            return Err("The zone has more than one SOA record.".to_string());
        }
        let mut sets: BTreeMap<Owner, BTreeMap<u16, Vec<Record>>> = BTreeMap::new();
        for record in records {
            if !record.owner.is_subdomain_of(&apex) {
                return Err(format!("{} is outside the zone {apex}.", record.owner));
            }
            // An RRSIG belongs with the type it covers, not in an RRset of
            // its own; it is grouped under RRSIG and matched later.
            let set = sets.entry(Owner(record.owner.clone())).or_default()
                .entry(record.rtype).or_default();
            // Duplicates are one record (RFC 2181 section 5).
            if !set.iter().any(|r| r.rdata == record.rdata && r.class == record.class) {
                set.push(record);
            }
        }
        Ok(Zone { apex, sets })
    }

    fn soa(&self) -> &Record {
        &self.sets[&Owner(self.apex.clone())][&rr::SOA][0]
    }

    /// RFC 9077: the NSEC and NSEC3 TTL is the lesser of the SOA's
    /// minimum field and the SOA's own TTL.
    fn negative_ttl(&self) -> u32 {
        let soa = self.soa();
        let minimum = u32::from_be_bytes(soa.rdata[soa.rdata.len() - 4..].try_into()
            .expect("four bytes"));
        minimum.min(soa.ttl)
    }

    /// Names at or below a delegation point other than the apex. The
    /// delegation point itself is not occluded: its NS is unsigned and its
    /// DS is signed.
    fn delegations(&self) -> Vec<Name> {
        self.sets.iter()
            .filter(|(owner, types)| owner.0 != self.apex && types.contains_key(&rr::NS))
            .map(|(owner, _)| owner.0.clone()).collect()
    }

    fn is_glue(&self, name: &Name, cuts: &[Name]) -> bool {
        cuts.iter().any(|cut| name.is_subdomain_of(cut) && !name.eq_ignore_case(cut))
    }
}

/// What to sign with and how.
pub struct Options {
    pub inception: u32,
    pub expiration: u32,
    /// `None` for NSEC; NSEC3 parameters otherwise.
    pub nsec3: Option<Nsec3Param>,
}

/// The RRSIG over an RRset: the header, then each record in canonical
/// form, sorted by canonical RDATA (RFC 4034 sections 3.1.8.1 and 6.3).
pub fn signed_data(header: &Rrsig, records: &[Record]) -> Result<Vec<u8>, String> {
    let owner = &records[0].owner;
    // A wildcard is signed under its own owner; an expansion would be
    // signed under the wildcard and checked with `labels` (RFC 4035
    // section 5.3.2). Every owner here is the zone's own.
    let mut forms: Vec<Vec<u8>> = records.iter()
        .map(|r| rr::canonical_rdata(r.rtype, &r.rdata))
        .collect::<Result<_, _>>()?;
    forms.sort();
    forms.dedup();
    let mut out = header.header();
    let mut head = owner.canonical().to_wire();
    head.extend_from_slice(&records[0].rtype.to_be_bytes());
    head.extend_from_slice(&records[0].class.to_be_bytes());
    head.extend_from_slice(&header.original_ttl.to_be_bytes());
    for rdata in forms {
        out.extend_from_slice(&head);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Ok(out)
}

fn sign_set(records: &[Record], key: &Key, dnskey: &Dnskey, signer: &Name,
            options: &Options) -> Result<Record, String> {
    let first = &records[0];
    let mut header = Rrsig {
        type_covered: first.rtype, algorithm: key.algorithm.number,
        labels: first.owner.rrsig_labels(), original_ttl: first.ttl,
        expiration: options.expiration, inception: options.inception,
        key_tag: keys::key_tag(&dnskey.to_rdata()), signer: signer.clone(),
        signature: Vec::new(),
    };
    header.signature = key.sign(&signed_data(&header, records)?)?;
    Ok(Record { owner: first.owner.clone(), ttl: first.ttl, class: first.class,
                rtype: rr::RRSIG, rdata: header.to_rdata() })
}

/// Every name between the apex and `name`, exclusive of both: the empty
/// non-terminals NSEC3 has to cover (RFC 5155 section 7.1).
fn ancestors_below(name: &Name, apex: &Name) -> Vec<Name> {
    let depth = name.labels().len() - apex.labels().len();
    (1..depth).map(|n| name.parent(n)).collect()
}

/// Sign a zone. Existing RRSIG, NSEC, NSEC3 and NSEC3PARAM records are
/// dropped and made again; the keys' DNSKEYs are added to the apex if
/// absent. Keys with the SEP flag sign the DNSKEY RRset and the others
/// sign the rest, unless one kind is missing, when every key signs
/// everything.
pub fn sign_zone(records: Vec<Record>, keys: &[(Key, u16)], options: &Options)
                 -> Result<Vec<Record>, String> {
    let mut records: Vec<Record> = records.into_iter()
        .filter(|r| !matches!(r.rtype, rr::RRSIG | rr::NSEC | rr::NSEC3 | rr::NSEC3PARAM))
        .collect();
    let mut zone = Zone::new(records.clone())?;
    let apex = zone.apex.clone();
    let apex_ttl = zone.soa().ttl;

    let mut dnskeys = Vec::new();
    for (key, flags) in keys {
        let dnskey = Dnskey { flags: *flags, protocol: 3, algorithm: key.algorithm.number,
                              public_key: key.public_key()? };
        let rdata = dnskey.to_rdata();
        if !records.iter().any(|r| r.rtype == rr::DNSKEY && r.owner.eq_ignore_case(&apex)
                               && r.rdata == rdata) {
            records.push(Record { owner: apex.clone(), ttl: apex_ttl, class: rr::CLASS_IN,
                                  rtype: rr::DNSKEY, rdata });
        }
        dnskeys.push(dnskey);
    }
    if let Some(param) = &options.nsec3 {
        records.push(Record { owner: apex.clone(), ttl: 0, class: rr::CLASS_IN,
                              rtype: rr::NSEC3PARAM,
                              rdata: Nsec3Param { flags: 0, ..param.clone() }.to_rdata() });
    }
    zone = Zone::new(records)?;
    let cuts = zone.delegations();
    let negative_ttl = zone.negative_ttl();

    // Denial of existence first, so its records are signed with the rest.
    let mut extra = Vec::new();
    let authoritative: Vec<(Name, Vec<u16>)> = zone.sets.iter()
        .filter(|(owner, _)| !zone.is_glue(&owner.0, &cuts))
        .map(|(owner, types)| (owner.0.clone(), types.keys().copied().collect()))
        .collect();
    let is_cut = |name: &Name| cuts.iter().any(|c| c.eq_ignore_case(name));
    match &options.nsec3 {
        None => {
            for (i, (name, types)) in authoritative.iter().enumerate() {
                let next = &authoritative[(i + 1) % authoritative.len()].0;
                let mut bits = types.clone();
                bits.extend([rr::NSEC, rr::RRSIG]);
                extra.push(Record { owner: name.clone(), ttl: negative_ttl, class: rr::CLASS_IN,
                                    rtype: rr::NSEC, rdata: rr::nsec_rdata(next, &bits) });
            }
        }
        Some(param) => {
            let mut hashed: BTreeMap<Vec<u8>, Vec<u16>> = BTreeMap::new();
            for (name, types) in &authoritative {
                let mut bits = types.clone();
                // An unsigned delegation has no RRSIG at its name.
                if !is_cut(name) || types.contains(&rr::DS) {
                    bits.push(rr::RRSIG);
                }
                hashed.insert(keys::nsec3_hash(name, param.hash_algorithm, &param.salt,
                                               param.iterations)?, bits);
                for ent in ancestors_below(name, &apex) {
                    let h = keys::nsec3_hash(&ent, param.hash_algorithm, &param.salt,
                                             param.iterations)?;
                    hashed.entry(h).or_default();
                }
            }
            let all: Vec<(&Vec<u8>, &Vec<u16>)> = hashed.iter().collect();
            for (i, (hash, bits)) in all.iter().enumerate() {
                let next = all[(i + 1) % all.len()].0.clone();
                let owner = apex.prepend(rr::base32hex(hash).to_ascii_lowercase().as_bytes())?;
                let rdata = Nsec3 { param: Nsec3Param { flags: 0, ..param.clone() },
                                    next_hashed: next, types: (*bits).clone() }.to_rdata();
                extra.push(Record { owner, ttl: negative_ttl, class: rr::CLASS_IN,
                                    rtype: rr::NSEC3, rdata });
            }
        }
    }

    let mut all_records: Vec<Record> = zone.sets.into_values()
        .flat_map(|types| types.into_values().flatten()).collect();
    all_records.extend(extra);
    let zone = Zone::new(all_records)?;

    let has_sep = keys.iter().any(|(_, f)| f & rr::SEP != 0);
    let has_zsk = keys.iter().any(|(_, f)| f & rr::SEP == 0);
    let mut signatures = Vec::new();
    for (owner, types) in &zone.sets {
        if zone.is_glue(&owner.0, &cuts) {
            continue;
        }
        for (rtype, set) in types {
            // At a delegation point only DS and the denial record are the
            // zone's own data (RFC 4035 section 2.2).
            if is_cut(&owner.0) && !matches!(*rtype, rr::DS | rr::NSEC | rr::NSEC3) {
                continue;
            }
            for ((key, flags), dnskey) in keys.iter().zip(&dnskeys) {
                let sep = flags & rr::SEP != 0;
                let wanted = if *rtype == rr::DNSKEY { sep || !has_sep } else { !sep || !has_zsk };
                if wanted {
                    signatures.push(sign_set(set, key, dnskey, &apex, options)?);
                }
            }
        }
    }
    let mut out: Vec<Record> = zone.sets.into_values()
        .flat_map(|types| types.into_values().flatten()).collect();
    out.extend(signatures);
    sort(&mut out);
    Ok(out)
}

/// Canonical order of owners, then type (SOA first at the apex, as a
/// master file reads best), then canonical RDATA.
pub fn sort(records: &mut [Record]) {
    records.sort_by(|a, b| {
        a.owner.canonical_cmp(&b.owner)
            .then_with(|| (a.rtype != rr::SOA).cmp(&(b.rtype != rr::SOA)))
            .then_with(|| covered(a).cmp(&covered(b)))
            .then_with(|| (a.rtype == rr::RRSIG).cmp(&(b.rtype == rr::RRSIG)))
            .then_with(|| rr::canonical_rdata(a.rtype, &a.rdata).unwrap_or_default()
                       .cmp(&rr::canonical_rdata(b.rtype, &b.rdata).unwrap_or_default()))
    });
}

fn covered(record: &Record) -> u16 {
    if record.rtype == rr::RRSIG {
        u16::from_be_bytes([record.rdata[0], record.rdata[1]])
    } else {
        record.rtype
    }
}

// ------------------------------------------------------------- verification --

/// What `verify_zone` found. A zone is good when `problems` is empty.
#[derive(Default, Debug)]
pub struct Report {
    pub rrsets: usize,
    pub signatures: usize,
    pub valid: usize,
    pub denial: &'static str,
    pub problems: Vec<String>,
}

/// Check every RRSIG in a zone against the apex DNSKEYs at time `now`,
/// that every authoritative RRset is signed by every algorithm the
/// DNSKEY RRset has (RFC 4035 section 2.2), and the NSEC or NSEC3 chain.
pub fn verify_zone(records: Vec<Record>, now: u32) -> Result<Report, String> {
    let zone = Zone::new(records)?;
    let apex = zone.apex.clone();
    let cuts = zone.delegations();
    let is_cut = |name: &Name| cuts.iter().any(|c| c.eq_ignore_case(name));
    let mut report = Report::default();

    let apex_sets = &zone.sets[&Owner(apex.clone())];
    let dnskeys: Vec<Dnskey> = apex_sets.get(&rr::DNSKEY).map(|set| {
        set.iter().filter_map(|r| Dnskey::parse(&r.rdata).ok()).collect()
    }).unwrap_or_default();
    let zone_keys: Vec<&Dnskey> = dnskeys.iter()
        .filter(|k| k.flags & rr::ZONE_KEY != 0 && k.protocol == 3).collect();
    if zone_keys.is_empty() {
        return Err(format!("{apex} has no zone keys in its DNSKEY RRset."));
    }
    let algorithms: BTreeSet<u8> = zone_keys.iter().map(|k| k.algorithm).collect();

    for (owner, types) in &zone.sets {
        if zone.is_glue(&owner.0, &cuts) {
            if types.contains_key(&rr::RRSIG) {
                report.problems.push(format!("{}: glue below a delegation has an RRSIG.",
                                            owner.0));
            }
            continue;
        }
        let sigs: Vec<Rrsig> = types.get(&rr::RRSIG).map(|set| {
            set.iter().filter_map(|r| Rrsig::parse(&r.rdata).ok()).collect()
        }).unwrap_or_default();
        for (rtype, set) in types {
            if *rtype == rr::RRSIG {
                continue;
            }
            let delegated_ns = is_cut(&owner.0) && !matches!(*rtype, rr::DS | rr::NSEC
                                                                   | rr::NSEC3);
            let covering: Vec<&Rrsig> = sigs.iter().filter(|s| s.type_covered == *rtype)
                .collect();
            if delegated_ns {
                if !covering.is_empty() {
                    report.problems.push(format!("{} {}: signed at a delegation point.",
                                                owner.0, rr::type_name(*rtype)));
                }
                continue;
            }
            report.rrsets += 1;
            let mut good: BTreeSet<u8> = BTreeSet::new();
            for sig in covering {
                report.signatures += 1;
                match check(sig, set, &zone_keys, &apex, now) {
                    Ok(()) => {
                        report.valid += 1;
                        good.insert(sig.algorithm);
                    }
                    Err(e) => report.problems.push(format!("{} {} RRSIG {} {}: {e}", owner.0,
                                                           rr::type_name(*rtype), sig.algorithm,
                                                           sig.key_tag)),
                }
            }
            for missing in algorithms.difference(&good) {
                report.problems.push(format!("{} {}: no valid signature by algorithm {}.",
                                            owner.0, rr::type_name(*rtype), missing));
            }
        }
    }

    let nsec3param = apex_sets.get(&rr::NSEC3PARAM)
        .and_then(|set| set.iter().find_map(|r| Nsec3Param::parse(&r.rdata).ok()));
    match nsec3param {
        Some(param) => {
            report.denial = "NSEC3";
            check_nsec3(&zone, &cuts, &param, &mut report.problems)?;
        }
        None => {
            report.denial = "NSEC";
            check_nsec(&zone, &cuts, &mut report.problems);
        }
    }
    Ok(report)
}

/// Serial number comparison (RFC 1982) for the validity window.
fn serial_le(a: u32, b: u32) -> bool {
    a == b || (b.wrapping_sub(a) as i32) > 0
}

fn check(sig: &Rrsig, set: &[Record], keys: &[&Dnskey], apex: &Name, now: u32)
         -> Result<(), String> {
    if !sig.signer.eq_ignore_case(apex) {
        return Err(format!("signed by {}, not the zone.", sig.signer));
    }
    if !serial_le(sig.inception, now) {
        return Err("not yet valid.".to_string());
    }
    if !serial_le(now, sig.expiration) {
        return Err("expired.".to_string());
    }
    if sig.labels > set[0].owner.rrsig_labels() {
        return Err("more labels than the owner has.".to_string());
    }
    // The signed data carries the Original TTL; the records may have a
    // lower TTL than that (RFC 4035 section 5.3.3), and not a higher one.
    if set[0].ttl > sig.original_ttl {
        return Err(format!("a TTL of {} above the original {}.", set[0].ttl,
                           sig.original_ttl));
    }
    let algorithm = keys::algorithm(sig.algorithm)?;
    let data = signed_data(sig, set)?;
    let mut tried = false;
    for key in keys.iter().filter(|k| k.algorithm == sig.algorithm
                                  && keys::key_tag(&k.to_rdata()) == sig.key_tag) {
        tried = true;
        if keys::verify(algorithm, &key.public_key, &data, &sig.signature)? {
            return Ok(());
        }
    }
    Err(if tried { "does not verify.".to_string() }
        else { "no DNSKEY with its tag and algorithm.".to_string() })
}

fn check_nsec(zone: &Zone, cuts: &[Name], problems: &mut Vec<String>) {
    let names: Vec<&Owner> = zone.sets.keys().filter(|o| !zone.is_glue(&o.0, cuts)).collect();
    for (i, owner) in names.iter().enumerate() {
        let types = &zone.sets[*owner];
        let Some(set) = types.get(&rr::NSEC) else {
            problems.push(format!("{}: no NSEC.", owner.0));
            continue;
        };
        let Ok((next, bits)) = rr::parse_nsec(&set[0].rdata) else {
            problems.push(format!("{}: an NSEC that does not parse.", owner.0));
            continue;
        };
        let expected_next = &names[(i + 1) % names.len()].0;
        if !next.eq_ignore_case(expected_next) {
            problems.push(format!("{}: NSEC names {next} next, and the next name is {}.",
                                  owner.0, expected_next));
        }
        let present: Vec<u16> = types.keys().copied().collect();
        if bits != present {
            problems.push(format!("{}: NSEC lists {:?}, the name has {:?}.", owner.0, bits,
                                  present));
        }
    }
}

fn check_nsec3(zone: &Zone, cuts: &[Name], param: &Nsec3Param, problems: &mut Vec<String>)
               -> Result<(), String> {
    let apex = &zone.apex;
    let is_cut = |name: &Name| cuts.iter().any(|c| c.eq_ignore_case(name));
    let hash = |name: &Name| keys::nsec3_hash(name, param.hash_algorithm, &param.salt,
                                              param.iterations);
    let mut chain: BTreeMap<Vec<u8>, Nsec3> = BTreeMap::new();
    for (owner, types) in &zone.sets {
        if let Some(set) = types.get(&rr::NSEC3) {
            let label = &owner.0.labels()[0];
            let h = rr::unbase32hex(std::str::from_utf8(label).unwrap_or(""))
                .map_err(|e| format!("{}: {e}", owner.0))?;
            chain.insert(h, Nsec3::parse(&set[0].rdata)?);
        }
    }
    let opt_out = chain.values().any(|n| n.param.flags & 1 != 0);

    // What the chain should hold: every authoritative name and every
    // empty non-terminal, hashed. Under opt-out an unsigned delegation,
    // and an empty non-terminal only it needs, may be left out
    // (RFC 5155 section 7.1); `optional` holds those.
    let mut expected: BTreeMap<Vec<u8>, (Name, Vec<u16>)> = BTreeMap::new();
    let mut optional: BTreeMap<Vec<u8>, (Name, Vec<u16>)> = BTreeMap::new();
    for (owner, types) in &zone.sets {
        if zone.is_glue(&owner.0, cuts) {
            continue;
        }
        // The NSEC3 records at a hashed owner are not the name's own data:
        // a name may also hold records of its own (RFC 5155 appendix A
        // has one), and those are what its NSEC3 lists.
        let own: Vec<u16> = types.keys().copied()
            .filter(|&t| t != rr::RRSIG && t != rr::NSEC3).collect();
        if own.is_empty() {
            continue;
        }
        let insecure = is_cut(&owner.0) && !types.contains_key(&rr::DS);
        let mut bits = own;
        if !insecure {
            bits.push(rr::RRSIG);
        }
        bits.sort_unstable();
        let target = if insecure && opt_out { &mut optional } else { &mut expected };
        target.insert(hash(&owner.0)?, (owner.0.clone(), bits));
        for ent in ancestors_below(&owner.0, apex) {
            target.entry(hash(&ent)?).or_insert((ent, Vec::new()));
        }
    }
    for h in expected.keys().cloned().collect::<Vec<_>>() {
        optional.remove(&h);
    }

    let hashes: Vec<&Vec<u8>> = chain.keys().collect();
    for (i, hash) in hashes.iter().enumerate() {
        let record = &chain[*hash];
        let next = hashes[(i + 1) % hashes.len()];
        if record.next_hashed != **next {
            problems.push(format!("NSEC3 {}: the next hash is not the next owner.",
                                  rr::base32hex(hash)));
        }
        if record.param.iterations != param.iterations || record.param.salt != param.salt
            || record.param.hash_algorithm != param.hash_algorithm {
            problems.push(format!("NSEC3 {}: parameters differ from NSEC3PARAM.",
                                  rr::base32hex(hash)));
        }
        match expected.get(*hash).or_else(|| optional.get(*hash)) {
            None => problems.push(format!("NSEC3 {}: matches no name in the zone.",
                                          rr::base32hex(hash))),
            Some((name, bits)) => {
                let mut listed = record.types.clone();
                listed.sort_unstable();
                if listed != *bits {
                    problems.push(format!("NSEC3 for {name}: lists {listed:?}, the name has \
                                           {bits:?}."));
                }
            }
        }
    }
    for (hash, (name, _)) in &expected {
        if !chain.contains_key(hash) {
            problems.push(format!("{name}: no NSEC3 ({}).", rr::base32hex(hash)));
        }
    }
    Ok(())
}

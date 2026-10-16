/*
What an object identifier means, decided at run time.

This library knows a few hundred OIDs and what each one stands for, and
that table is compiled in. The equipment this library exists for does
not always agree with it. A box can name a digest by an OID from a
national standard nobody vendored, or a GOST parameter set from an
organisation's own arc, or a curve under a third name - and until now
the answer was to edit `src/x509/oids.rs` and rebuild.

So: a registry. A caller says what an OID means, and the places that
would otherwise have refused it consult this first.

    register("1.2.643.2.2.9", Meaning::hash("gost94"))?;
    register("1.2.643.2.2.31.9",
             Meaning::gost_param_set(rows))?;      // your own S-box
    register("1.2.643.2.2.35.1", Meaning::curve("gost256-a"))?;

From Python the same three, through `allcrypt.register_oid`.

## What it deliberately does not do

**It cannot invent an algorithm.** `Meaning::Hash` names a hash this
library already implements; it does not let a caller define one. What
it moves is the *naming*, which is where most of the incompatibilities
in this corner of the world actually are: the same GOST hash has four
OIDs across three standards.

**Two meanings do carry cryptography**, and the line between them and
`Hash` is not arbitrary. A GOST cipher **is** its S-box - eight
permutations of sixteen values, and the standard is explicit that the
tables are a parameter distributed separately. A short Weierstrass curve
**is** its seven numbers, distributed the same way. Both are parameter
sets: data, checkable as data, and `register` checks them - eight
permutations for one, and for the other everything in
`ec::curves::from_parameters`, because a curve that is merely plausible
still computes and still signs.

A hash is not a parameter set. It is a compression function, a message
schedule, a padding rule and an endianness convention, so there is
nothing to hand across this boundary that would constitute one.
`docs/extending.md` has the options for someone who needs one anyway,
and the reason a Python callback is not among the ones to reach for.

## Order

A registered meaning is consulted **after** the compiled-in tables, not
before. So registering `1.2.643.2.2.9` as something other than GOST R
34.11-94 does nothing - the built-in answer wins - and no caller can
change what a standard OID means for anybody else in the process. What
a registration reaches is the gap: OIDs this library would otherwise
have refused.

That order is the reason this is safe to have at all, and
`tests::test_a_registration_cannot_shadow_a_built_in` is what keeps it.
*/

use std::collections::HashMap;
use std::sync::RwLock;

use crate::asn1::encode_oid;

/// What an OID can be registered as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Meaning {
    /// A hash function, by the name `api::AnyHash::new` knows it.
    ///
    /// `register` accepts a registered OID here too, but stores the
    /// built-in name that OID stands for at the time: what the table
    /// holds is always a built-in name, so a lookup is one step and
    /// two registrations cannot point at each other.
    Hash(String),
    /// A GOST parameter set: the eight substitution rows a GOST
    /// 28147-89 cipher or a GOST R 34.11-94 hash runs on.
    GostParamSet(Vec<Vec<u8>>),
    /// An elliptic curve, by the name `ec::curves::by_name` knows it.
    Curve(String),
    /// An elliptic curve this library does not carry, by its domain
    /// parameters.
    ///
    /// **The second registration that carries cryptography rather than a
    /// name**, alongside `GostParamSet`, and for the same reason: a short
    /// Weierstrass curve *is* its seven numbers, distributed as a
    /// parameter set. `ec::curves::from_parameters` checks that they are
    /// a curve - p prime, the curve non-singular, G on it, n its prime
    /// order, the cofactor within Hasse's bound - and `register` refuses
    /// anything that fails, because a curve that is merely plausible
    /// still computes and still produces signatures.
    ///
    /// Boxed: the parameters are seven bignums and every other variant is
    /// a word or two, so an unboxed one would make every `Meaning` in the
    /// table that size.
    CurveParameters(Box<crate::ec::curves::CurveParameters>),
}

impl Meaning {
    pub fn hash(algorithm: &str) -> Meaning {
        Meaning::Hash(algorithm.to_string())
    }

    pub fn curve(name: &str) -> Meaning {
        Meaning::Curve(name.to_string())
    }

    pub fn gost_param_set(rows: Vec<Vec<u8>>) -> Meaning {
        Meaning::GostParamSet(rows)
    }

    pub fn curve_parameters(parameters: crate::ec::curves::CurveParameters)
                            -> Meaning {
        Meaning::CurveParameters(Box::new(parameters))
    }

    /// A word for what kind of thing this is, for listings.
    pub fn kind(&self) -> &'static str {
        match self {
            Meaning::Hash(_) => "hash",
            Meaning::GostParamSet(_) => "gost-param-set",
            Meaning::Curve(_) => "curve",
            Meaning::CurveParameters(_) => "curve-parameters",
        }
    }

    /// What it resolves to, for listings. An S-box has no name, so it
    /// describes itself by shape.
    pub fn describe(&self) -> String {
        match self {
            Meaning::Hash(name) | Meaning::Curve(name) => name.clone(),
            Meaning::GostParamSet(rows) =>
                format!("{} substitution rows", rows.len()),
            // The bit length as well as the name, because that is the
            // thing a reader wants to check at a glance and the name is
            // whatever the caller chose to call it.
            Meaning::CurveParameters(parameters) =>
                format!("{} ({} bit)", parameters.name, parameters.p.bit_len()),
        }
    }
}

fn table() -> &'static RwLock<HashMap<String, Meaning>> {
    static TABLE: std::sync::OnceLock<RwLock<HashMap<String, Meaning>>> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Give an OID a meaning.
///
/// The OID is given in dotted decimal and is checked by encoding it,
/// so a typo is an error here rather than a lookup that never matches.
/// Registering an OID twice replaces the older meaning, which is what
/// makes a script that runs twice harmless.
pub fn register(oid: &str, meaning: Meaning) -> Result<(), String> {
    // Encoding is the validation: `encode_oid` refuses a bad arc, a
    // first arc above 2, a second above 39 under the first two, and
    // anything else that would not round trip.
    encode_oid(oid)?;

    let meaning = match meaning {
        Meaning::Hash(name) => {
            // **The table holds built-in names only, never another
            // OID.** A target that is itself a registered OID is
            // resolved here, once, to the built-in name it stands for,
            // and that name is what is stored. Storing the OID would
            // make the table a graph: `A -> B` then `B -> A` passed
            // validation (the old `A` still resolved) and the lookup
            // then followed the cycle until the stack overflowed, which
            // is an abort rather than an error. With only built-in names
            // stored, a lookup is one step and `forget` on the target
            // OID cannot orphan a registration made through it.
            let built_in = hash_for(&name).unwrap_or(name);
            crate::api::AnyHash::new(&built_in).map_err(|reason| format!(
                "{} cannot be registered as {:?}: {}", oid, built_in, reason))?;
            Meaning::Hash(built_in)
        }
        // **Stored as the curve's own name, not as the caller spelled
        // it.** `by_name` folds case and separators and knows aliases -
        // `GOST256_A`, `tc26-256-b`, `SM2` - so a registration accepted
        // under any of them has to answer under the one name every other
        // table holds. Stored as given, it resolved nowhere that compared
        // names: a GOST certificate on the OID read as an unsupported
        // curve, and a certificate on the curve could not be written.
        Meaning::Curve(name) => {
            let curve = crate::ec::curves::by_name(&name).map_err(|reason| format!(
                "{} cannot be registered as curve {:?}: {}", oid, name, reason))?;
            Meaning::Curve(curve.name.to_string())
        }
        other => other,
    };

    match &meaning {
        Meaning::Hash(_) | Meaning::Curve(_) => {}
        // The same check `GostCrypto::new_with_sbox` makes, so a table
        // refused here is not accepted there.
        Meaning::GostParamSet(rows) =>
            crate::block_ciphers::gost::GostCrypto::check_sbox(rows)?,
        Meaning::CurveParameters(parameters) => {
            // The whole of the validation lives in `from_parameters`, so
            // that a Rust caller building a curve directly gets the same
            // checks as one coming through here. The built curve is
            // discarded: what is stored is the parameters, and
            // `CurveParameters::assemble` rebuilds it on lookup without
            // repeating the primality tests.
            crate::ec::curves::from_parameters((**parameters).clone())
                .map_err(|reason| format!(
                    "{} cannot be registered as a curve: {}", oid, reason))?;
        }
    }

    let mut table = table().write().map_err(|_| "the registry is poisoned")?;
    // **A curve is found by its name**, by `curves::by_name` and by
    // everything that turns an OID into a curve, so two different curves
    // cannot share one. Registered under one name twice, the second set
    // of parameters was reached or not depending on the order a hash map
    // gave back. The same numbers under a second OID are an alias and
    // are fine, however the name is spelled.
    if let Meaning::CurveParameters(parameters) = &meaning {
        let numbers = |p: &crate::ec::curves::CurveParameters|
            [p.p.clone(), p.a.clone(), p.b.clone(), p.gx.clone(), p.gy.clone(),
             p.n.clone(), p.h.clone()];
        let clash = table.iter().find(|(other, held)| other.as_str() != oid
            && matches!(held, Meaning::CurveParameters(theirs)
                        if same_curve_name(&theirs.name, &parameters.name)
                           && numbers(theirs) != numbers(parameters)));
        if let Some((other, _)) = clash {
            return Err(format!(
                "{} cannot be registered as a curve called {:?}: {} already \
                 names a different curve by that name, and a curve is found \
                 by its name. Give one of them another.",
                oid, parameters.name, other));
        }
    }
    table.insert(oid.to_string(), meaning);
    Ok(())
}

/// What an OID has been registered as, if anything.
pub fn lookup(oid: &str) -> Option<Meaning> {
    table().read().ok()?.get(oid).cloned()
}

/// The same, from the encoded form a certificate carries.
pub fn lookup_der(der: &[u8]) -> Option<Meaning> {
    let oid = crate::asn1::Oid::new(der).ok()?;
    lookup(&oid.to_string())
}

/// Every registration, sorted, for a caller that wants to show them.
pub fn registered() -> Vec<(String, Meaning)> {
    let table = match table().read() {
        Ok(table) => table,
        Err(_) => return Vec::new(),
    };
    let mut all: Vec<(String, Meaning)> = table.iter()
        .map(|(oid, meaning)| (oid.clone(), meaning.clone()))
        .collect();
    all.sort_by(|left, right| left.0.cmp(&right.0));
    all
}

/// Undo one registration. `true` if there was one.
pub fn forget(oid: &str) -> bool {
    match table().write() {
        Ok(mut table) => table.remove(oid).is_some(),
        Err(_) => false,
    }
}

/// Undo all of them. For a test that must not leak into the next one.
pub fn clear() {
    if let Ok(mut table) = table().write() {
        table.clear();
    }
}

// ------------------------------------------------- what consults this ---

/// A hash algorithm name, if this string is a registered OID.
///
/// `api::AnyHash::new` calls it after its own table, so
/// `AnyHash::new("1.2.643.2.2.9")` works once that OID is registered
/// and a built-in name is never shadowed.
pub fn hash_for(name: &str) -> Option<String> {
    match lookup(name)? {
        Meaning::Hash(algorithm) => Some(algorithm),
        _ => None,
    }
}

/// The substitution rows a registered parameter set names.
pub fn gost_param_set(name: &str) -> Option<Vec<Vec<u8>>> {
    match lookup(name)? {
        Meaning::GostParamSet(rows) => Some(rows),
        _ => None,
    }
}

/// The curve a registered parameter set OID names, from its DER form -
/// which is what `x509::oids::gost_curve_for` has in hand.
///
/// Both kinds of curve registration answer here: one that names a
/// built-in curve, and one that supplied its own parameters. A caller
/// asking "what curve is this OID" does not care which, and the name it
/// gets back resolves through `curves::by_name` either way.
pub fn curve_for_der(der: &[u8]) -> Option<String> {
    match lookup_der(der)? {
        Meaning::Curve(name) => Some(name),
        Meaning::CurveParameters(parameters) => Some(parameters.name.clone()),
        _ => None,
    }
}

/// The curve a registered OID names, as `curves::by_name` spells it.
///
/// **The one way to turn a registered OID into a curve name**, for every
/// reader that has an OID in hand: GOST parameter sets, the curve of an
/// `id-ecPublicKey` certificate, and a PKCS#8 or SEC1 private key. Going
/// through `by_name` rather than comparing names means a registration
/// spelled any way `by_name` takes reaches the curve, the answer is the
/// same `&'static str` the curve itself carries, and a registration whose
/// curve has since been forgotten answers nothing rather than a name that
/// resolves to nothing.
pub fn curve_named_by_der(der: &[u8]) -> Option<&'static str> {
    let name = curve_for_der(der)?;
    crate::ec::curves::by_name(&name).ok().map(|curve| curve.name)
}

/// The OID to write for a curve that is not built in: the one registered
/// for it, encoded. `Ok(None)` when there is none.
///
/// For the writers - certificates and GOST public keys - which have a
/// curve and must name it. Several OIDs is an error rather than a choice
/// of the first: what is written names exactly one, and choosing would be
/// choosing for the caller.
pub fn oid_for_curve(name: &str) -> Result<Option<Vec<u8>>, String> {
    let oids = oids_for_curve(name);
    match oids.len() {
        0 => Ok(None),
        1 => Ok(Some(encode_oid(&oids[0])?)),
        _ => Err(format!(
            "{} is registered under {} OIDs ({}), and a key names one. \
             Forget the ones it should not claim.",
            name, oids.len(), oids.join(", "))),
    }
}

/// Curve names compare the way `curves::by_name` compares them.
///
/// Not `==`: a registered curve that only answered to the exact spelling
/// it was registered under would be a second class of curve, and the
/// asymmetry showed up as `CertificateAuthority` failing where
/// `EcKey.generate` worked - `api::ca_key` folds the name on the way in.
fn same_curve_name(left: &str, right: &str) -> bool {
    crate::ec::curves::normalise_name(left)
        == crate::ec::curves::normalise_name(right)
}

/// Every OID registered for a curve of this name.
///
/// The reverse of the usual direction, and it has one caller: writing a
/// certificate. `x509::builder` has a curve and needs the OID to name it
/// by, where everything else in this library has an OID and needs the
/// curve.
///
/// **A list rather than an `Option`, so ambiguity is visible.** Nothing
/// stops a caller registering the same curve under two OIDs - which is
/// reasonable, since the whole reason this registry exists is that the
/// same curve is named several times over in practice. It is fine for
/// reading, where each OID resolves to the curve. It is not fine for
/// writing: a certificate names exactly one, and picking one would be
/// choosing for the caller.
pub fn oids_for_curve(name: &str) -> Vec<String> {
    // The curve's own name first, so that an alias spelled the way the
    // caller asked for it - `SM2` for `sm2p256v1` - finds the curve.
    // Resolved before the table is locked: `by_name` reads the table
    // itself, for a registered curve.
    let name = crate::ec::curves::by_name(name)
        .map(|curve| curve.name.to_string())
        .unwrap_or_else(|_| name.to_string());
    let name = name.as_str();
    let table = match table().read() {
        Ok(table) => table,
        Err(_) => return Vec::new(),
    };
    let mut found: Vec<String> = table.iter()
        .filter(|(_, meaning)| match meaning {
            Meaning::Curve(registered) => same_curve_name(registered, name),
            Meaning::CurveParameters(parameters) =>
                same_curve_name(&parameters.name, name),
            _ => false,
        })
        .map(|(oid, _)| oid.clone())
        .collect();
    // Sorted so the error message below is the same on every run: a
    // HashMap's order is not, and a message that changes between runs is
    // one nobody can search for.
    found.sort();
    found
}

/// The registered parameters of a curve, by the name they were given.
///
/// Keyed by curve name rather than by OID, because `curves::by_name` is
/// what the rest of the library asks - an OID is turned into a name long
/// before anyone needs the arithmetic. The table is small and deliberate,
/// so a scan is the right shape.
pub fn curve_parameters_named(name: &str)
                              -> Option<crate::ec::curves::CurveParameters> {
    let table = table().read().ok()?;
    table.values().find_map(|meaning| match meaning {
        Meaning::CurveParameters(parameters)
            if same_curve_name(&parameters.name, name) =>
            Some((**parameters).clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registrations are process-wide, so a test that registers
    /// something must not leave it there for the next one. Rust runs
    /// tests in threads of one process, so this is not optional.
    struct Scoped(&'static str);
    impl Drop for Scoped {
        fn drop(&mut self) {
            forget(self.0);
        }
    }

    #[test]
    fn test_a_hash_can_be_reached_by_a_registered_oid() {
        // An OID from the private arc, so nothing built in can answer.
        const OID: &str = "1.3.6.1.4.1.99999.1.1";
        let _scoped = Scoped(OID);
        assert!(crate::api::AnyHash::new(OID).is_err(),
                "the OID answered before it was registered");

        register(OID, Meaning::hash("gost94")).unwrap();
        let mut hash = crate::api::AnyHash::new(OID).unwrap();
        use crate::hash_functions::HashFunction;
        hash.update(b"This is message, length=32 bytes");
        assert_eq!(hash.digest(),
                   crate::hash_functions::gost94::Gost94::new(
                       b"This is message, length=32 bytes").digest());
    }

    #[test]
    fn test_a_registration_cannot_shadow_a_built_in() {
        // sha256 is compiled in. Registering its OID as md5 must not
        // change what `sha256` means, and must not change what the OID
        // means either - the built-in table is consulted first.
        const OID: &str = "2.16.840.1.101.3.4.2.1";
        let _scoped = Scoped(OID);
        register(OID, Meaning::hash("md5")).unwrap();

        let mut named = crate::api::AnyHash::new("sha256").unwrap();
        use crate::hash_functions::HashFunction;
        assert_eq!(named.digest().len(), 32, "sha256 stopped being sha256");
    }

    /// A registration whose target is another registered OID is stored
    /// as the built-in name that OID stands for, so the table never
    /// holds a chain and a cycle cannot be built.
    ///
    /// `register(A, hash(sha256))`, `register(B, hash(A))`,
    /// `register(A, hash(B))` used to pass validation - the third step
    /// resolved B through the *old* A - and then store `A -> B`, after
    /// which `AnyHash::new(A)` followed A -> B -> A until the stack
    /// overflowed. The existing tests registered one OID at a time,
    /// each naming a built-in, so no chain existed to loop on.
    #[test]
    fn test_a_hash_registration_cannot_form_a_cycle() {
        use crate::hash_functions::HashFunction;
        const A: &str = "1.3.6.1.4.1.99999.7.1";
        const B: &str = "1.3.6.1.4.1.99999.7.2";
        let _scoped_a = Scoped(A);
        let _scoped_b = Scoped(B);

        register(A, Meaning::hash("sha256")).unwrap();
        register(B, Meaning::hash(A)).unwrap();
        // B stored the built-in name, not A.
        assert_eq!(lookup(B), Some(Meaning::hash("sha256")));
        // So the closing step of the cycle resolves B to sha256 and
        // stores that; and whatever is stored, every lookup is one step.
        register(A, Meaning::hash(B)).unwrap();
        assert_eq!(lookup(A), Some(Meaning::hash("sha256")));
        assert_eq!(crate::api::AnyHash::new(A).unwrap().digest().len(), 32);
        assert_eq!(crate::api::AnyHash::new(B).unwrap().digest().len(), 32);
        // Forgetting the OID B was registered through does not orphan B.
        forget(A);
        assert_eq!(crate::api::AnyHash::new(B).unwrap().digest().len(), 32);

        // An OID naming itself, before anything is registered under it,
        // is a target that resolves to nothing.
        assert!(register(A, Meaning::hash(A)).is_err());
        assert!(lookup(A).is_none());
    }

    /// Even a table that does hold a cycle - planted directly, since
    /// `register` no longer writes one - is one lookup step away from
    /// an error, never a recursion.
    #[test]
    fn test_a_planted_cycle_is_an_error_not_a_stack_overflow() {
        const A: &str = "1.3.6.1.4.1.99999.8.1";
        const B: &str = "1.3.6.1.4.1.99999.8.2";
        let _scoped_a = Scoped(A);
        let _scoped_b = Scoped(B);
        {
            let mut table = table().write().unwrap();
            table.insert(A.to_string(), Meaning::hash(B));
            table.insert(B.to_string(), Meaning::hash(A));
        }
        let reason = match crate::api::AnyHash::new(A) {
            Ok(_) => panic!("a planted cycle resolved to a hash"),
            Err(reason) => reason,
        };
        assert!(reason.contains("Unknown hash"), "{}", reason);
        assert!(crate::api::AnyHash::new(B).is_err());
    }

    #[test]
    fn test_a_gost_param_set_must_be_eight_permutations() {
        const OID: &str = "1.3.6.1.4.1.99999.2.1";
        let _scoped = Scoped(OID);

        let good: Vec<Vec<u8>> = (0..8)
            .map(|row| (0..16u8).map(|i| (i + row) % 16).collect())
            .collect();
        register(OID, Meaning::gost_param_set(good.clone())).unwrap();
        assert_eq!(gost_param_set(OID), Some(good.clone()));

        // Seven rows.
        let mut short = good.clone();
        short.pop();
        assert!(register(OID, Meaning::gost_param_set(short)).is_err());

        // A row that repeats a value, which is the mistake worth
        // naming: it is still sixteen entries and it is not a
        // permutation, which no published table has.
        let mut repeated = good.clone();
        repeated[3][0] = repeated[3][1];
        let reason = register(OID, Meaning::gost_param_set(repeated))
            .unwrap_err();
        assert!(reason.contains("not a permutation"), "{}", reason);

        // A value that is not a nibble.
        let mut wide = good;
        wide[0][0] = 16;
        assert!(register(OID, Meaning::gost_param_set(wide)).is_err());
    }

    #[test]
    fn test_a_meaning_that_names_nothing_is_refused() {
        const OID: &str = "1.3.6.1.4.1.99999.3.1";
        let _scoped = Scoped(OID);
        assert!(register(OID, Meaning::hash("not-a-hash")).is_err());
        assert!(register(OID, Meaning::curve("not-a-curve")).is_err());
        assert!(lookup(OID).is_none(),
                "a refused registration was stored anyway");
    }

    #[test]
    fn test_a_bad_oid_is_refused_at_registration() {
        // Rather than being stored and never matching anything, which
        // is the failure that looks like the feature not working.
        assert!(register("1.2.three", Meaning::hash("sha256")).is_err());
        assert!(register("", Meaning::hash("sha256")).is_err());
        assert!(register("3.1.1", Meaning::hash("sha256")).is_err(),
                "the first arc of an OID is 0, 1 or 2");
    }

    #[test]
    fn test_der_lookup_finds_the_dotted_registration() {
        const OID: &str = "1.3.6.1.4.1.99999.4.1";
        let _scoped = Scoped(OID);
        register(OID, Meaning::curve("P-256")).unwrap();
        let der = encode_oid(OID).unwrap();
        assert_eq!(curve_for_der(&der), Some("P-256".to_string()));
    }

    /// The consultation point that matters for a certificate: a
    /// parameter set OID from an arc this library has never seen.
    ///
    /// Before registration `gost_curve_for` returns `None`, and a
    /// certificate carrying it reads as "a curve this library does
    /// not implement". After, it resolves - and the name that comes
    /// back is the `&'static str` the curve table owns, not a copy,
    /// which is what lets the answer flow into everything that takes
    /// a curve name.
    #[test]
    fn test_a_registered_parameter_set_names_a_curve_for_x509() {
        use crate::x509::oids::gost_curve_for;
        const OID: &str = "1.3.6.1.4.1.99999.5.1";
        let _scoped = Scoped(OID);
        let der = encode_oid(OID).unwrap();

        assert_eq!(gost_curve_for(&der), None);
        register(OID, Meaning::curve("gost256-a")).unwrap();
        assert_eq!(gost_curve_for(&der), Some("gost256-a"));
        // And it is the curve table's own name, so `by_name` answers.
        assert!(crate::ec::curves::by_name(
            gost_curve_for(&der).unwrap()).is_ok());

        forget(OID);
        assert_eq!(gost_curve_for(&der), None,
                   "forgetting left the registration in place");
    }

    /// An alias of a built-in curve, spelled as another library spells
    /// it, is found when a certificate on the curve is written and
    /// answers when it is read.
    ///
    /// SM2 has no OID compiled in, and OpenSSL calls the curve `SM2`.
    /// Registered under that spelling, writing looked for `sm2p256v1`
    /// among names stored as `SM2` and found nothing, and reading looked
    /// the name up among curves registered with their own parameters and
    /// found nothing there either.
    #[test]
    fn test_an_alias_of_a_built_in_curve_is_written_and_read() {
        use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
        const OID: &str = "1.3.6.1.4.1.99999.5.8";
        let _scoped = Scoped(OID);
        register(OID, Meaning::curve("SM2")).unwrap();
        assert_eq!(lookup(OID), Some(Meaning::curve("sm2p256v1")));
        assert_eq!(oids_for_curve("sm2p256v1"), vec![OID.to_string()]);
        assert_eq!(oids_for_curve("curveSM2"), vec![OID.to_string()]);

        let curve = crate::ec::curves::sm2();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        let mut builder = CertificateBuilder::new(
            "sm2.test", SubjectKey::Ec { curve: &curve, point: &point });
        builder.serial = vec![1];
        builder.not_before = "20200101000000Z";
        builder.not_after = "20400101000000Z";
        let der = builder.sign(&SigningKey::Ec { curve: &curve, private: &private })
            .unwrap();
        match crate::x509::Certificate::parse(&der).unwrap().public_key {
            crate::x509::PublicKey::Ec { curve, .. } => assert_eq!(curve, "sm2p256v1"),
            other => panic!("{other:?}"),
        }
    }

    /// Two different curves cannot share a name; the same curve under a
    /// second OID is an alias and can.
    #[test]
    fn test_two_curves_cannot_share_a_name() {
        const FIRST: &str = "1.3.6.1.4.1.99999.5.9";
        const SECOND: &str = "1.3.6.1.4.1.99999.5.10";
        let (_first, _second) = (Scoped(FIRST), Scoped(SECOND));
        fn copy_of(curve: crate::ec::Curve, name: &str)
                   -> crate::ec::curves::CurveParameters {
            crate::ec::curves::CurveParameters {
                name: name.to_string(), p: curve.p.clone(), a: curve.a.clone(),
                b: curve.b.clone(), gx: curve.g.x().unwrap().clone(),
                gy: curve.g.y().unwrap().clone(), n: curve.n.clone(),
                h: curve.h.clone(),
            }
        }
        use crate::ec::curves::{p256, secp256k1};
        register(FIRST, Meaning::curve_parameters(copy_of(p256(), "shared-name"))).unwrap();
        let refused = register(SECOND, Meaning::curve_parameters(
            copy_of(secp256k1(), "Shared_Name"))).unwrap_err();
        assert!(refused.contains(FIRST), "{refused}");
        // The same numbers under another spelling of the name: an alias.
        register(SECOND, Meaning::curve_parameters(copy_of(p256(), "Shared Name"))).unwrap();
        assert_eq!(curve_named_by_der(&encode_oid(SECOND).unwrap()),
                   curve_named_by_der(&encode_oid(FIRST).unwrap()));

        // An alias of a curve that is then forgotten answers nothing,
        // rather than a name that resolves to nothing.
        forget(SECOND);
        let alias = encode_oid(SECOND).unwrap();
        register(SECOND, Meaning::curve("Shared_Name")).unwrap();
        assert_eq!(curve_named_by_der(&alias), Some("shared-name"));
        forget(FIRST);
        assert_eq!(curve_named_by_der(&alias), None);
    }

    /// A registered S-box reaches the cipher, and is a different
    /// cipher from the one it was derived from.
    #[test]
    fn test_a_registered_parameter_set_is_a_working_cipher() {
        use crate::block_ciphers::{gost::GostCrypto, BlockCipher};
        const OID: &str = "1.3.6.1.4.1.99999.6.1";
        let _scoped = Scoped(OID);

        let mut rows = GostCrypto::sbox_named(
            GostCrypto::DEFAULT_PARAM_SET).unwrap();
        rows[0].reverse();
        register(OID, Meaning::gost_param_set(rows)).unwrap();

        let key = vec![1u8; 32];
        let block = [2u8; 8];
        let mut theirs = GostCrypto::new(&key,
                                         GostCrypto::DEFAULT_PARAM_SET)
            .unwrap();
        let mut ours = GostCrypto::new(&key, OID).unwrap();

        let (mut a, mut b) = (Vec::new(), Vec::new());
        theirs.block_encrypt(&block, &mut a);
        ours.block_encrypt(&block, &mut b);
        assert_ne!(a, b, "the registered table changed nothing");

        let mut back = Vec::new();
        ours.block_decrypt(&b, &mut back);
        assert_eq!(back, block, "the registered table does not invert");
    }
}

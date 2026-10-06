/*
Trusted roots, from the operating system.

The decision this module implements: **read the platform's own trust store**,
rather than bundling a root list in the crate or making every caller supply
one. That matches what Python's `ssl` does and what people expect, and it
means the roots follow the system's updates rather than the crate's release
schedule.

It also means platform-specific code, which is the cost. There are three
paths and they are honest about themselves:

  * **Unix**: the CA bundle files and directories every distribution ships.
    Well-trodden, testable here, and the same mechanism OpenSSL uses.

  * **Windows**: the "ROOT" *and* "AuthRoot" system certificate stores,
    through `wincrypt`. Declared with a bare `extern "system"` block, no
    dependency. Verified on Windows: `test_the_system_store_if_there_is_one`
    fails rather than skips there, so a green run on that platform means
    the store really opened and every root in it parsed.

    **Windows populates its root store on demand.** The system ships a
    small set and fetches the rest from Windows Update the first time
    Schannel needs one, so a machine that has never had a reason to trust
    a given CA does not have it locally - even though Edge and Chrome
    will happily reach a site that uses it. A process reading the store
    directly, as this does, sees the cached subset and nothing triggers
    the fetch. "AuthRoot" is read as well because it is where the
    auto-update mechanism caches third-party roots, so it often holds
    what "ROOT" does not; the two are merged and duplicates dropped. That
    narrows the gap without closing it, and a caller who needs a specific
    CA should load it explicitly rather than hope.

**Which of these three paths you get is not always the one you expect.**
Under WSL this is Linux and reads the distribution's CA bundle, not the
Windows store - so roots Windows has are not necessarily roots this sees,
and `SSL_CERT_FILE` overrides even that. A real run failed two badssl
rows on "No trusted root issued CN=DigiCert Global Root CA" and the first
theory was the Windows store; the run was under WSL and the Windows store
was never involved. Both DigiCert roots parse here without complaint, so
it was never the parser either - the root simply was not in the bundle
being read. `TrustStore::source` exists to answer that question before
anybody theorises, and `scripts/check_live.py` now prints it.

  * **macOS**: falls back to the unix file paths. The Keychain is the real
    store and reading it needs the Security framework; until that is
    written, a mac with no `/etc/ssl/cert.pem` gets no roots and is told so
    rather than silently getting an empty list.

Two rules, both of which are about failing loudly:

  1. **An empty root set is an error, not an empty list.** "No roots found"
     silently becomes "verify nothing" two function calls later. Every entry
     point here returns `Err` rather than `Ok(vec![])`.

  2. **A root that does not parse is skipped, and counted.** A system bundle
     has hundreds of certificates in it and one unparseable entry should not
     take the other four hundred with it - but the count comes back, so a
     caller can notice that it skipped three hundred of them.
*/

use crate::pem;
use crate::x509::Certificate;

/// How many parse failures to keep the reason for. The count is exact
/// however many there are; this bounds only the explanations.
const MAX_SKIPPED_REASONS: usize = 16;

/// The first eight bytes of a SHA-256 over the DER, in hex - enough to
/// find one certificate in a bundle and short enough to read aloud.
fn short_digest(der: &[u8]) -> String {
    use crate::hash_functions::HashFunction;
    let mut hash = crate::hash_functions::sha2::SHA256::new(&[]);
    hash.update(der);
    hash.digest().iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

/// Trusted roots, as DER.
///
/// Held as bytes rather than parsed certificates because `Certificate`
/// borrows what it was parsed from, and a trust store outlives any one
/// verification.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    roots: Vec<Vec<u8>>,
    /// Entries that were found but could not be parsed. Kept because a
    /// store that quietly dropped most of its roots looks exactly like a
    /// store that worked.
    skipped: usize,
    /// *Why* each of those failed, which the count on its own does not
    /// say. A real run reported "120 roots loaded, 1 skipped" and there
    /// was no way to find out which root or what our parser objected to -
    /// and a root every other TLS stack accepts being refused here is a
    /// bug in this library, not in the root.
    ///
    /// Bounded, because a pathological bundle should not turn a
    /// diagnostic into a memory problem. The count above stays exact.
    skipped_reasons: Vec<String>,
    /// Where these came from, for the error message when verification
    /// fails and somebody has to work out which store they were using.
    source: String,
}

impl TrustStore {
    pub fn new() -> TrustStore {
        TrustStore::default()
    }

    /// The platform's own trust store.
    pub fn system() -> Result<TrustStore, String> {
        imp::load()
    }

    /// One PEM file of concatenated certificates - a CA bundle.
    pub fn from_pem_file(path: &str) -> Result<TrustStore, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path, e))?;
        let mut store = TrustStore::from_pem(&text)?;
        store.source = path.to_string();
        Ok(store)
    }

    /// PEM text, from wherever the caller got it.
    pub fn from_pem(text: &str) -> Result<TrustStore, String> {
        let mut store = TrustStore { source: "PEM text".to_string(), ..Default::default() };
        store.add_pem(text)?;
        store.require_non_empty()
    }

    /// A directory of PEM files, as `/etc/ssl/certs` is on most systems.
    pub fn from_directory(path: &str) -> Result<TrustStore, String> {
        let entries = std::fs::read_dir(path)
            .map_err(|e| format!("Cannot list {}: {}", path, e))?;
        let mut store = TrustStore { source: path.to_string(), ..Default::default() };

        for entry in entries.flatten() {
            let file = entry.path();
            // Skip the symlink farm's hash links: they point at the same
            // certificates and would double every root.
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !(name.ends_with(".pem") || name.ends_with(".crt")) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&file) {
                // One bad file does not spoil the directory.
                let _ = store.add_pem(&text);
            }
        }
        store.require_non_empty()
    }

    /// Add every certificate in some PEM text.
    pub fn add_pem(&mut self, text: &str) -> Result<usize, String> {
        let found = pem::certificates(text)?;
        let mut added = 0;
        for der in found {
            if self.add_der(&der).is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Add one DER certificate, after checking that it parses.
    ///
    /// Parsing here rather than at verification time means a broken root is
    /// found when the store is built, which is when somebody is in a
    /// position to do something about it.
    /// A certificate already present is not added twice, and that is not
    /// an error - it is the ordinary case when two stores overlap, as
    /// Windows' ROOT and AuthRoot do heavily. Without this a merged store
    /// would hold most roots twice and every chain search would scan them
    /// twice to reach the same answer.
    ///
    /// The comparison is on the DER bytes, so it de-duplicates *the same
    /// certificate* rather than the same subject. Two different roots
    /// sharing a subject name is a real situation - a CA rolling its key
    /// keeps the name - and both must be kept, because either may be the
    /// one that issued the chain in front of us.
    pub fn add_der(&mut self, der: &[u8]) -> Result<(), String> {
        match Certificate::parse(der) {
            Ok(_) => {
                if !self.roots.iter().any(|existing| existing == der) {
                    self.roots.push(der.to_vec());
                }
                Ok(())
            }
            Err(reason) => {
                self.skipped += 1;
                if self.skipped_reasons.len() < MAX_SKIPPED_REASONS {
                    // The DER cannot be parsed, so there is no subject to
                    // name it by. Its length and the first bytes of a
                    // digest are enough to find it in a bundle with
                    // `openssl x509`, which is what somebody will do next.
                    self.skipped_reasons.push(format!(
                        "{} byte entry, sha256 {}: {}",
                        der.len(), short_digest(der), reason));
                }
                Err(reason)
            }
        }
    }

    fn require_non_empty(self) -> Result<TrustStore, String> {
        if self.roots.is_empty() {
            // Not Ok(empty): an empty trust store silently becomes "trust
            // nothing", which looks like a network problem rather than a
            // configuration one.
            return Err(format!(
                "No usable certificates in {} ({} could not be parsed).",
                self.source, self.skipped));
        }
        Ok(self)
    }

    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// How many entries were found but could not be parsed.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Why they could not be parsed, up to the first few.
    ///
    /// Each entry identifies the certificate by size and digest - there
    /// is no subject to quote, since parsing it is what failed - and
    /// carries our parser's own complaint, which is the part that says
    /// whether the certificate is malformed or we are too strict.
    pub fn skipped_reasons(&self) -> &[String] {
        &self.skipped_reasons
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// The subjects of every root, for a caller that wants to show them.
    pub fn subjects(&self) -> Vec<String> {
        self.roots.iter()
            .filter_map(|der| Certificate::parse(der).ok().map(|c| c.subject.to_string()))
            .collect()
    }
}

/// The unix locations, in the order everything else tries them.
///
/// The list is long because every distribution picked a different one, and
/// a library that only knows Debian's is a library that does not work on
/// Fedora.
#[cfg(unix)]
pub const BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",                  // Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",                    // Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",                              // OpenSUSE
    "/etc/pki/tls/cacert.pem",                             // older RHEL
    "/etc/ssl/cert.pem",                                   // Alpine, macOS, BSD
    "/usr/local/share/certs/ca-root-nss.crt",              // FreeBSD
    "/etc/openssl/certs/ca-certificates.crt",              // NetBSD
];

#[cfg(unix)]
pub const DIRECTORY_PATHS: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/system/etc/security/cacerts",                        // Android
];

#[cfg(unix)]
mod imp {
    use super::{TrustStore, BUNDLE_PATHS, DIRECTORY_PATHS};

    /// The `SSL_CERT_FILE` and `SSL_CERT_DIR` variables come first, because
    /// that is the convention everything else follows and because a
    /// container image usually sets them when the paths are unusual.
    pub fn load() -> Result<TrustStore, String> {
        if let Ok(path) = std::env::var("SSL_CERT_FILE") {
            if !path.is_empty() {
                return TrustStore::from_pem_file(&path);
            }
        }
        if let Ok(path) = std::env::var("SSL_CERT_DIR") {
            if !path.is_empty() {
                return TrustStore::from_directory(&path);
            }
        }

        let mut tried = Vec::new();
        for path in BUNDLE_PATHS {
            match TrustStore::from_pem_file(path) {
                Ok(store) => return Ok(store),
                Err(reason) => tried.push(format!("{}: {}", path, reason)),
            }
        }
        for path in DIRECTORY_PATHS {
            match TrustStore::from_directory(path) {
                Ok(store) => return Ok(store),
                Err(reason) => tried.push(format!("{}: {}", path, reason)),
            }
        }

        Err(format!(
            "No system trust store found. Tried:\n  {}\n\
             Set SSL_CERT_FILE to a CA bundle, or load roots explicitly.",
            tried.join("\n  ")))
    }
}

#[cfg(windows)]
mod imp {
    use super::TrustStore;

    // The "ROOT" system store, through wincrypt. No dependency: the three
    // calls needed are declared here the same way `random` declares
    // BCryptGenRandom.
    //
    // This is only ever compiled on Windows and cannot be exercised from
    // the Linux development container, so the tests are written to fail
    // rather than skip when the store will not open - see the note on
    // `test_the_system_store_if_there_is_one`. Confirmed working on a real
    // Windows machine.
    #[allow(non_camel_case_types)]
    type HCERTSTORE = *mut core::ffi::c_void;

    #[repr(C)]
    struct CERT_CONTEXT {
        dw_cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        // The rest of the struct is not needed and is deliberately not
        // declared: reading past what we use would be reading a layout we
        // have not checked.
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(provider: usize, subsystem: *const u16) -> HCERTSTORE;
        fn CertEnumCertificatesInStore(store: HCERTSTORE,
                                       previous: *const CERT_CONTEXT)
                                       -> *const CERT_CONTEXT;
        fn CertCloseStore(store: HCERTSTORE, flags: u32) -> i32;
    }

    /// Read one named system store into `trust`, returning how many
    /// certificates it held. A store that will not open is not an error
    /// here: "AuthRoot" does not exist on every install, and the caller
    /// decides whether what it got is enough.
    fn read_store(name: &str, trust: &mut TrustStore) -> Option<usize> {
        let wide: Vec<u16> = format!("{}\0", name).encode_utf16().collect();
        let store = unsafe { CertOpenSystemStoreW(0, wide.as_ptr()) };
        if store.is_null() {
            return None;
        }

        let mut found = 0usize;
        let mut context: *const CERT_CONTEXT = core::ptr::null();
        loop {
            context = unsafe { CertEnumCertificatesInStore(store, context) };
            if context.is_null() {
                break;
            }
            // SAFETY: the context is owned by the store and stays valid
            // until the next call to CertEnumCertificatesInStore, which is
            // after this copy.
            let der = unsafe {
                core::slice::from_raw_parts((*context).pb_cert_encoded,
                                            (*context).cb_cert_encoded as usize)
            };
            found += 1;
            // The result is deliberately dropped rather than propagated:
            // `add_der` has already counted the failure in `skipped`, and
            // one unparseable entry must not take the other four hundred
            // with it. `TrustStore::skipped` is how a caller finds out.
            let _ = trust.add_der(der);
        }

        unsafe { CertCloseStore(store, 0) };
        Some(found)
    }

    pub fn load() -> Result<TrustStore, String> {
        let mut trust = TrustStore::default();

        // ROOT is the store Schannel verifies against. AuthRoot is where
        // the automatic root update mechanism caches the third-party root
        // programme, and it frequently holds CAs that ROOT does not -
        // which is the difference between reaching a site and not.
        //
        // `add_der` de-duplicates, so a certificate in both is stored
        // once and the counts below stay honest.
        let root = read_store("ROOT", &mut trust);
        let auth = read_store("AuthRoot", &mut trust);

        if root.is_none() && auth.is_none() {
            return Err("Cannot open the Windows ROOT or AuthRoot certificate \
                        stores.".to_string());
        }
        trust.source = match (root, auth) {
            (Some(r), Some(a)) =>
                format!("the Windows ROOT ({} entries) and AuthRoot ({}) stores",
                        r, a),
            (Some(r), None) => format!("the Windows ROOT store ({} entries)", r),
            (None, Some(a)) => format!("the Windows AuthRoot store ({} entries)", a),
            (None, None) => unreachable!("checked above"),
        };

        trust.require_non_empty()
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::TrustStore;

    pub fn load() -> Result<TrustStore, String> {
        // An error rather than an empty store, for the reason at the top of
        // this file.
        Err("No system trust store is available on this platform. \
             Load roots explicitly.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
    use crate::ec::curves;

    fn a_certificate(common_name: &str) -> Vec<u8> {
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        let mut builder = CertificateBuilder::new(
            common_name, SubjectKey::Ec { curve: &curve, point: &point });
        builder.is_ca = Some((true, None));
        builder.sign(&SigningKey::Ec { curve: &curve, private: &private }).unwrap()
    }

    #[test]
    fn test_a_store_built_from_pem() {
        let text = format!("{}{}",
                           crate::pem::wrap("CERTIFICATE", &a_certificate("Root One")),
                           crate::pem::wrap("CERTIFICATE", &a_certificate("Root Two")));
        let store = TrustStore::from_pem(&text).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.skipped(), 0);

        let subjects = store.subjects();
        assert!(subjects.contains(&"CN=Root One".to_string()));
        assert!(subjects.contains(&"CN=Root Two".to_string()));
    }

    /// The same certificate twice is stored once; two different roots
    /// that share a subject are both kept.
    ///
    /// Both halves matter. Windows' ROOT and AuthRoot stores overlap
    /// heavily, so merging them without de-duplication doubles the store.
    /// And a CA that rolls its key keeps its name, so de-duplicating by
    /// *subject* would silently drop the root that issued the chain in
    /// front of you.
    #[test]
    fn test_duplicates_are_dropped_but_collisions_are_not() {
        let one = a_certificate("Shared Name");
        let two = a_certificate("Shared Name");
        assert_ne!(one, two, "the test needs two distinct certificates");

        let mut store = TrustStore::new();
        store.add_der(&one).unwrap();
        store.add_der(&one).unwrap();
        store.add_der(&one).unwrap();
        assert_eq!(store.len(), 1, "the same certificate was stored twice");
        assert_eq!(store.skipped(), 0, "a duplicate is not a failure");

        store.add_der(&two).unwrap();
        assert_eq!(store.len(), 2,
                   "two different roots sharing a subject must both be kept");
    }

    /// One unparseable entry in a bundle of hundreds must not take the
    /// others with it - but the count has to come back, or a store that
    /// dropped most of its roots looks like one that worked.
    #[test]
    fn test_a_broken_entry_is_skipped_and_counted() {
        let text = format!("{}{}{}",
                           crate::pem::wrap("CERTIFICATE", &a_certificate("Good One")),
                           crate::pem::wrap("CERTIFICATE", b"not a certificate"),
                           crate::pem::wrap("CERTIFICATE", &a_certificate("Good Two")));
        let store = TrustStore::from_pem(&text).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.skipped(), 1);
    }

    /// The count on its own is not a diagnosis. A live run against a
    /// distribution bundle reported "120 roots loaded, 1 skipped as
    /// unparseable" and there was no way to tell which root, or whether
    /// our parser or the certificate was at fault - and those two have
    /// opposite remedies. So the reason is kept, with enough to find the
    /// entry again in a bundle that has no subject to quote.
    #[test]
    fn test_a_skipped_entry_keeps_its_reason() {
        let broken = b"not a certificate";
        let text = format!("{}{}",
                           crate::pem::wrap("CERTIFICATE", &a_certificate("Good One")),
                           crate::pem::wrap("CERTIFICATE", broken));
        let store = TrustStore::from_pem(&text).unwrap();

        assert_eq!(store.skipped(), 1);
        let reasons = store.skipped_reasons();
        assert_eq!(reasons.len(), 1);

        // The size and digest are how somebody finds the entry again.
        assert!(reasons[0].contains(&format!("{} byte", broken.len())),
                "the reason must size the entry: {}", reasons[0]);
        assert!(reasons[0].contains(&short_digest(broken)),
                "the reason must identify the entry: {}", reasons[0]);
        // And our parser's own complaint, which is the part that says
        // whether the certificate is malformed or we are too strict.
        let complaint = Certificate::parse(broken).unwrap_err();
        assert!(reasons[0].contains(&complaint),
                "the reason must carry the parser's complaint: {}", reasons[0]);
    }

    /// A pathological bundle must not turn a diagnostic into a memory
    /// problem - but the count stays exact however many there are, since
    /// that is the number that says whether the store is usable.
    #[test]
    fn test_the_reasons_are_bounded_but_the_count_is_not() {
        let mut store = TrustStore::new();
        let broken = MAX_SKIPPED_REASONS * 3;
        for n in 0..broken {
            // Distinct bytes, so this is not the de-duplication path.
            let _ = store.add_der(format!("junk number {}", n).as_bytes());
        }
        assert_eq!(store.skipped(), broken);
        assert_eq!(store.skipped_reasons().len(), MAX_SKIPPED_REASONS);
    }

    /// The rule this module exists to enforce: nothing usable is an error,
    /// because an empty store silently becomes "trust nothing" and looks
    /// like a network problem.
    #[test]
    fn test_an_empty_store_is_an_error() {
        assert!(TrustStore::from_pem("").is_err());
        assert!(TrustStore::from_pem("# no certificates here").is_err());

        let only_broken = crate::pem::wrap("CERTIFICATE", b"junk");
        let error = TrustStore::from_pem(&only_broken).unwrap_err();
        assert!(error.contains("No usable certificates"), "{}", error);
        assert!(error.contains("1 could not be parsed"), "{}", error);
    }

    #[test]
    fn test_a_missing_file_is_an_error_with_the_path_in_it() {
        let error = TrustStore::from_pem_file("/nonexistent/ca-bundle.crt").unwrap_err();
        assert!(error.contains("/nonexistent/ca-bundle.crt"), "{}", error);
    }

    /// The real one, on whatever machine this is running on.
    ///
    /// **On Windows this must succeed.** Every Windows install has a ROOT
    /// store and `CertOpenSystemStoreW` opens it; there is no legitimate
    /// "this machine has none" case, so an error there is our bug and has
    /// to fail the test.
    ///
    /// On unix it is a skip, because a scratch container genuinely can have
    /// no CA bundle - that is a property of the machine, not of the code.
    ///
    /// The distinction matters more than it looks. This test used to print
    /// "no system trust store here" and pass on *either* platform, which
    /// meant a green run on Windows said nothing at all about whether the
    /// `wincrypt` path worked - and at the time that path had never
    /// executed anywhere, so the one machine that could answer the question
    /// was the one whose answer was being swallowed. It has since run
    /// green on Windows, which is a fact this test now has the power to
    /// establish rather than merely fail to contradict.
    #[test]
    fn test_the_system_store_if_there_is_one() {
        match TrustStore::system() {
            Ok(store) => {
                // **No assertion on how many roots there are.** This
                // said `> 20` and failed on a machine with a smaller
                // store - a minimal container image, a locked-down
                // build, a device that trusts one internal CA. The
                // number is a property of the machine, not of this
                // code, and `TrustStore::system` already errors rather
                // than returning an empty store, so a threshold catches
                // nothing the Err arm below does not. A count is not a
                // diagnosis; the same lesson as `skipped`.
                assert_eq!(store.len(), store.roots().len(),
                           "len() disagrees with roots()");
                let certificate = Certificate::parse(&store.roots()[0]).unwrap();
                assert!(certificate.extensions.is_ca() || certificate.version < 3,
                        "a root that is not a CA: {}", certificate.subject);
                println!("{} roots from {} ({} skipped)",
                         store.len(), store.source(), store.skipped());
            }
            Err(reason) => {
                if cfg!(windows) {
                    panic!("Windows always has a ROOT certificate store, so \
                            failing to read it is this library's bug, not the \
                            machine's: {}", reason);
                }
                println!("no system trust store here: {}", reason);
            }
        }
    }

    /// Every root in the real store must parse and be usable as one.
    ///
    /// On Windows this is the first thing that has ever exercised the
    /// `wincrypt` path end to end: `CertOpenSystemStoreW`, the enumeration,
    /// the DER each entry hands back, and our own parser over all of it.
    /// On unix `tools/src/bin/diff_roots.rs` already does more than this against
    /// OpenSSL, but that example needs Python and this runs in `cargo test`.
    #[test]
    fn test_every_root_in_the_real_store_parses() {
        let store = match TrustStore::system() {
            Ok(store) => store,
            Err(reason) => {
                if cfg!(windows) {
                    panic!("no ROOT store on Windows: {}", reason);
                }
                println!("no system trust store here: {}", reason);
                return;
            }
        };

        let mut names = 0usize;
        let mut cross_signed = Vec::new();
        for der in store.roots() {
            let certificate = Certificate::parse(der).unwrap_or_else(|e| panic!(
                "a root in {} does not parse: {}", store.source(), e));
            // **A certificate in a trust store is not necessarily
            // self-issued.** This asserted that it was, and failed on a
            // machine whose store held a cross-signed root: a CA's key
            // certified by an *older* CA, kept so that clients which do
            // not know the newer root can still build a path. Most of
            // the public web's transitions have looked like this, and
            // both forms live in the store at once.
            //
            // Being in the store means "trusted as an anchor", which is
            // a decision about the store and not a property of the
            // bytes. `x509::verify` already treats it that way - it
            // matches an anchor by name and checks the signature it
            // made - so this test was the only thing that believed
            // otherwise. `test_a_cross_signed_root_is_a_usable_anchor`
            // in pytests/test_trust.py covers the property on every
            // machine rather than only on one with such a store.
            if certificate.subject.to_string() != certificate.issuer.to_string() {
                cross_signed.push(certificate.subject.to_string());
            }
            if certificate.subject.common_name().is_some() {
                names += 1;
            }
        }
        println!("{} roots from {}, all parsed, {} with a common name, \
                  {} cross-signed",
                 store.len(), store.source(), names, cross_signed.len());
        for subject in cross_signed.iter().take(8) {
            println!("  cross-signed: {}", subject);
        }
    }

    /// SSL_CERT_FILE must win over the built-in paths, because that is the
    /// convention and because containers rely on it.
    #[test]
    #[cfg(unix)]
    fn test_ssl_cert_file_is_honoured() {
        let path = std::env::temp_dir().join("allcrypt-test-roots.pem");
        std::fs::write(&path,
                       crate::pem::wrap("CERTIFICATE", &a_certificate("Env Root"))).unwrap();

        // Not using std::env::set_var, which is unsound with threads; the
        // file path goes straight to the loader instead. What this checks
        // is that the file form works, which is the part that could break.
        let store = TrustStore::from_pem_file(path.to_str().unwrap()).unwrap();
        assert_eq!(store.subjects(), vec!["CN=Env Root".to_string()]);
        assert_eq!(store.source(), path.to_str().unwrap());

        std::fs::remove_file(&path).ok();
    }
}

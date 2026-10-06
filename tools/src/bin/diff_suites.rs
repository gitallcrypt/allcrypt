// The cipher suite registry, dumped for comparison against OpenSSL's own.
// Verified by scripts/diff_check.py.
//
// A wrong code in this table is invisible: the suite simply never matches,
// so a client silently never negotiates it and a server's choice is
// reported as unknown. Nothing fails, nothing logs, and the suite that was
// supposed to let us talk to an old box quietly does not exist. OpenSSL
// knows the real numbers, so we ask it.
use allcrypt::tls::suites::{self, Selection, Strength};

fn main() {
    for suite in suites::ALL {
        println!("suite {:04x} {} {} {} {} {} {} {}",
                 suite.code,
                 suite.name,
                 if suite.openssl_name.is_empty() { "-" } else { suite.openssl_name },
                 suite.key_exchange.name(),
                 suite.cipher.name(),
                 suite.mac.name(),
                 suite.strength.name(),
                 suite.is_implemented());
    }

    // The selections, so the checker can confirm that nothing broken is in
    // the default one - a claim that is easy to make and easy to break by
    // editing a single strength label.
    println!("selection modern {}", Selection::modern().codes().iter()
             .map(|c| format!("{:04x}", c)).collect::<Vec<_>>().join(","));
    println!("selection legacy {}", Selection::legacy().codes().iter()
             .map(|c| format!("{:04x}", c)).collect::<Vec<_>>().join(","));

    let insecure = suites::ALL.iter()
        .filter(|s| s.strength == Strength::Insecure)
        .map(|s| format!("{:04x}", s.code))
        .collect::<Vec<_>>();
    println!("insecure {}", insecure.join(","));

    eprintln!("{} suites in the registry", suites::ALL.len());
}

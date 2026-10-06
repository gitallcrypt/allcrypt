/*
SSH: the Secure Shell protocol's cryptography (RFC 4250 to 4254 and the
documents that extend them).

Built bottom up, each piece checked against OpenSSH before the next is
started:

  * `wire` - RFC 4251's data types, which everything else is made of.
  * `keys` - public key blobs, `authorized_keys` lines and fingerprints.
  * `cipher` - the ciphers by SSH name, in OpenSSH's `cipher_crypt`
    shape, for packets and for private key files alike.
  * `private_key` - `openssh-key-v1` files, plain and encrypted with
    bcrypt_pbkdf (`kdf::bcrypt_pbkdf`).
  * `signature` - signature blobs for every key type and RSA hash, and
    SSHSIG (`ssh-keygen -Y sign`).
  * `kex` - the key exchange methods, the exchange hash and the key
    derivation.
  * `mac`, `transport` - SSH's MACs, and the binary packet protocol in
    both modes (encrypt-and-MAC, encrypt-then-MAC) and with the AEAD
    ciphers.
  * `msg`, `negotiate` - the message numbers, and KEXINIT: the
    algorithms both ends arrive at and the keys they derive, shared by
    the two ends.
  * `client` - a sans-I/O client: key exchange, host key check,
    authentication, one command on a session channel.
  * `server` - a sans-I/O server: key exchange signed with its host
    keys, public key and password authentication, one session channel
    whose command the caller runs.

OpenSSH 10.0 is the witness, and 7.4 for the older algorithms.
`scripts/make_ssh_vectors.py` records what its `ssh-keygen` says into
`vectors/ssh_keys.vec`; `scripts/check_ssh_client.py` and
`scripts/check_ssh_server.py` record whole sessions with its `sshd` and
its `ssh`; the tests read those files, and none of them need OpenSSH or
the network.
*/

pub mod cipher;
pub mod client;
pub mod keys;
pub mod kex;
pub mod mac;
pub mod msg;
pub mod negotiate;
pub mod private_key;
pub mod server;
pub mod signature;
pub mod transport;
pub mod wire;

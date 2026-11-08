# age files to SSH keys

Read by `examples/products/age`'s offline tests; `ssh.vec` lists every
file and what opens it. Written by `scripts/make_age_ssh_fixtures.py`.

- `ed25519`, `rsa` and `ed25519-encrypted` (passphrase `key passphrase`),
  with their `.pub` halves: test keys made by `ssh-keygen` for these
  files and nothing else.
- `plain-*`: the plaintexts.
- `age-*` and `rage-*`: encrypted by age 1.1.1 and rage 0.11.1 to one
  key or to all three.
- `ours-*`: encrypted by the age example from a seeded generator, and
  decrypted by both age and rage before being kept.

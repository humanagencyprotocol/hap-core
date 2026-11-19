# Device-keys vectors (experimental)

JSON test vectors for `deviceKeys` (`src/device-keys/`). One runner, three places to run it:

- vitest: `test/device-keys.test.ts` (against the source)
- Node: `node test/vectors/device-keys/run-node.mjs [dist/index.mjs | dist/device-keys/index.mjs]`
- browsers: `runner.mjs` has no Node imports; load it with the vector files and the built bundle.

A case is `{ id, op, input, expect }`; `expect` is a value shape or `{ error: "NAME" }`.

## How they were made

1. `pnpm build`, then `node generate.mjs` writes all files. Ed25519 and hashes are deterministic.
   ECDSA P-256 keys and signatures are random, so a second run changes the check keys, the
   proofs and everything that hashes them (chain hashes, grants, pairing). Run it only on purpose.
2. `python3 -I patch-hardening.py` then adds the cases of the review hardening (required
   `expect` on grants and decisions, stored-head, extra signatures, labels, COSE, QR, hello).
   It patches the generated JSON in place; `generate.mjs` alone does not produce those cases.

Device labels in the data are fictional ("Alice's MacBook"). Labels are inside signed bytes, so
changing one means regenerating and re-patching.

`identity.json` (cancel and override) is made by `generate-identity.mjs` instead, which builds its own
two chains and leaves every other file untouched. Run it only on purpose (random ECDSA keys).

`team.json` (member list, anchor, leave, team trust; DEC-73) is made by `generate-team.mjs` the same way:
it builds its own chains and leaves every other file untouched. Run it only on purpose (random ECDSA keys).

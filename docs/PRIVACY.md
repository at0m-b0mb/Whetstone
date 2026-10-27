# Privacy — what must not reach the weights, and what stops it

This document exists because of one asymmetry. A corpus file can be grepped and
edited. A published checkpoint cannot. Everything below follows from that.

It describes **what the code in this tree does**, not what the remediation
intended. Where a defence is partial, the section says so and names the gap.
Where a claim in a comment is wrong, this document says it is wrong rather than
repeating it.

**No value appears in this file.** Not a path with a volume name in it, not an
address, not a name. Commands are written against the repository's own `data`
symlink (`data/corpus/...`), which is what `training/corpus/build.py` already
defaults to — partly for portability and partly because the mount point's name
is itself a needle the verifier scans for, and a privacy document that leaks is
the failure this project has already made once.

---

## 1. The threat model

Every `<|obs|>` in the trajectory register is a real read of a real machine, and
that is the point of the corpus — but a real read of **this** machine returns the
operator's account name, home directory, host name, per-user temp directory,
interface MAC addresses, bound IPv6 addresses, the ISP-delegated /64 those sit
in, and the names of mounted volumes. Forty-six other adapters walk this
filesystem and can put the same values into a document body or an `ident` field
without being asked. A corpus is the thing a language model memorises, and a
published checkpoint is **not greppable and not removable**: you cannot scan
weights for a string, you cannot delete one out of them, and the only remedy is
to throw the run away and retrain. So the corpus is the last place where a
leak is still cheap, and that is the only reason any of the machinery below
exists.

> A leak in a file costs an hour. The same leak in a checkpoint costs the run.

Two other facts shape the design. **The identifiers he cannot change are the
ones that matter most** — a host can be renamed in a second, a burned-in
interface MAC cannot be renamed at all, and a delegated /64 is a subscriber and
geographic identifier that reaches every device behind it. And **this is a
security corpus**, which means it is full of `192.0.2.0/24`, `2001:db8::/32`,
reserved MAC addresses and `user@example.com` **on purpose**, in RFCs, nuclei
templates and YARA rules. A detector that counts those as leaks buries the real
ones, and a gate with false positives gets switched off by the first person it
annoys and then protects nothing. Every classifier in this tree therefore
answers "not identity" for documentation space, and `verify.py --calibrate`
reports precision and recall against fixtures built before any corpus pass.

---

## 2. The defences, as layers

Each layer is named with the function that implements it, because a defence you
cannot find in the tree is a defence nobody can check.

### Layer 0 — exclusion, before anything is collected

`training/corpus/sources/ownrepos.py` is the only source built from this
machine's own filesystem, and therefore the only source that can carry a third
party's personal data. Two filters run before a document exists:

- `_SKIP_PARTS` drops dependency trees, toolchain caches, virtualenvs and build
  output. This is what makes the source's licence declaration true: an audit
  measured **54.2% of its shipped characters** as vendored ESP-IDF and
  PlatformIO documentation carried under a string reading "all repositories are
  this author's own work". `build.py` refuses a *blank* licence; nothing was
  checking a *false* one.
- `_roster_section` drops **the whole document** when it finds a heading that
  introduces people followed by two or more person-shaped entries, or one entry
  that also carries an address. See §4 for why exclusion and not scrubbing.

### Layer 1 — the build chokepoint

`training/corpus/build.py::_redacted` is the single function every document
passes through, called from inside the per-source document loop. It covers
`doc.text` **and** `doc.ident`. The `ident` half is not symmetry for its own
sake: several adapters build `ident` from a filesystem path (`logsamples` from
the repository path, `metasploit` from the module path,
`cloudsec`/`sigma`/`nuclei`/`elastic` from relative paths), it is written into
the shipped JSONL, and it had no redaction and no check at all. It never reaches
the tokenizer, which reads `row["text"]` only — it reaches everybody who reads or
is sent the corpus file, which is the population this is about.

`_scrubbed` runs **addresses first, then identity**, and the order is
load-bearing. The identity table holds the account name; on this machine the
account name is a substring of the operator's own address. Redacting identity
first would rewrite that address into something the host-address needle set no
longer matches, and the one rule with no exception anywhere would silently stop
firing.

`_reredact_mutated` runs the chokepoint **again** after `_strip_boilerplate`,
the last transform that edits text. It is expected to be a no-op on every
document, and that is why it is there: the alternative is an argument that
line-granular deletion can never join two halves of a literal, and an invariant
resting on an argument about a transform somebody will add later is not an
invariant. When it is not a no-op it prints that as a finding.

`_preflight_redaction` refuses **before the first byte is fetched** on two
conditions, because both are knowable at the start and discovering either after
an hour of fetching costs the hour:

1. `training.trajectories` will not import, so `redact_identity` is unavailable.
   This used to be caught inside the document loop as a per-source "parse
   failed", and the build carried on writing unredacted text for forty-seven
   sources.
2. The identity table is **empty**. An empty table makes `redact_identity`
   return every document byte-for-byte with nothing logged, which produces the
   same output and the same log as a build where redaction ran and found
   nothing. `--allow-unidentified-host` proceeds anyway and the log states in
   capitals that nothing the run writes carries an identity guarantee.

### Layer 2 — the identity table

`training/trajectories.py::_identity_table` is built from the operating system
at runtime. **Never configured and never persisted**, for two distinct reasons:
a configured list is a list of the leaks somebody already noticed, and a
persisted list is a new leak with a filename.

What it reads: the account name (`getpass`), the account's display name
(`pwd`'s GECOS field — the one value in an observation that identifies a human
rather than a machine), the home path, every per-user temp directory this
account owns, both spellings of the host name, and — this is the layer the
audit forced — the **network**: interface MAC addresses, bound IPv4 and IPv6
addresses, the /64 prefix of each global address, and the names of mounted
volumes.

**The /64 prefix is an entry in its own right**, and that is deliberate. Two of
the addresses the audit found belong to *other* devices on the same /64 —
observed, not bound here, so no amount of reading this machine's interfaces
can enumerate them. The prefix entry is the only thing that reaches them, and it
rewrites the half of the address that identifies the subscriber line.

Four properties worth stating because the obvious implementation gets each one
wrong:

- **Substitute, never delete.** `/Users/<name>/Public` becomes
  `/Users/operator/Public`, not `<home>/Public`. A corpus full of angle-bracket
  holes teaches the model that observations contain angle-bracket holes, and at
  serving time it meets a real path it has no shape for.
- **Never substitute a name that is not identity.** `_NOT_IDENTITY` and a
  four-character floor keep the table off `root`, `runner`, `ubuntu` and
  friends. A corpus built as `root` would otherwise rewrite every
  `"runs_as":"root"` in thirteen thousand documents and teach the model a world
  in which nothing runs as root. A redactor that quietly corrupts the corpus is
  worse than the leak it was added to fix.
- **Longest-first, and the order is load-bearing.** `re` matches an alternation
  leftmost-first, not longest-first, so the home path must precede the bare
  account name or the shorter rule half-substitutes the path and the longer one
  never fires. The /64 prefix sits below the full addresses for the same reason.
- **Idempotent.** `_assign` refuses any replacement that contains a literal the
  table is going to substitute, and a cross-pair guard at the end drops any
  remaining loop. That is what makes a second `redact_identity` pass a no-op,
  and it is why the re-redaction in Layer 1 is safe to run unconditionally.

**Varied replacements, because privacy and generalisation are one pass and two
problems.** Privacy is satisfied by *any* substitution. Generalisation is
satisfied only by a *varied* one. The audit measured 253 distinct machine
literals repeated a mean 947 times each; collapsing them onto a single `<HOST>`
token passes every privacy gate and makes the model worse, because it replaces a
distribution with a new constant. So each network kind draws from a pool keyed
on a digest of the literal — documentation /64s from `2001:db8::/32`, interface
identifiers of deliberately mixed shape, RFC 7042 documentation MACs, RFC1918
host-octet tails that avoid every octet networking examples already use. Each
pool is at least double the number of distinct literals of its kind, so the
assignment is injective (two interfaces must not come out with the same MAC —
that is not a world that exists), and very much smaller than the occurrence
count, so the model meets each replacement thousands of times. A pool that runs
out is recorded as a lookup failure rather than wrapping around.

Every address on one real /64 is given the same documentation /64, so "these two
addresses are on the same network" survives redaction as a fact about the text.
The RFC1918 block is kept and only the host bits move, because the block is what
distinguishes a flat home network from a routed lab and that distinction is
signal, not identity.

**Fail closed, and two kinds of empty.** A machine with genuinely nothing
identifying about it — `root` in `/root` on a hex-named container with nothing
routable bound — is leaking nothing, and returning text unchanged is correct. A
machine whose *lookups failed* is a machine the table knows nothing about, and
the previous version returned Mac-captured text unchanged and silently in
exactly that case. `_identity_failures()` separates them: it names which lookup
failed (as `account:OSError`, a kind and an exception type, never a value), and
both `redact_identity` and `identity_leaks` raise rather than answer.

**One matcher, not two folds.** The substituter and the verifier now run the
same compiled pattern and resolve the replacement by group index. The previous
version compiled with `re.IGNORECASE` while `identity_leaks` compared
`str.lower()` substrings, and those two disagree in both directions: a document
could be rewritten by a check that called it clean, or called clean by a check
the substituter would have rewritten. On this account name the disagreement is
reachable and made the substituter raise `KeyError` mid-build.

### Layer 3 — email, and the per-source policy

Email redaction used to live in `ownrepos.py` and nowhere else, as a courtesy.
It had also **never been run**: the module's mtime was twenty days later than
the corpus file's, and the shipped document still carried every address with not
one placeholder anywhere in 208,346 documents. From the source tree alone, a
redactor that was added and never run is indistinguishable from one that ran and
found nothing.

So the pass moved to the chokepoint, where no adapter can forget it, and the
policy is written down instead of being whatever one adapter happened to do.
`_email_replacement` applies four tests in order:

1. **An address of the operator's is rewritten in every source, including the
   exempt ones.** This is the one rule with no exception anywhere. He can
   publish his own address on his own website whenever he likes; a checkpoint is
   not a place he can un-publish it from. The needles come from `git config` and
   the environment, live only in that process, and are never printed, written or
   put in an exception message — the build reports a **count**, so that "nothing
   was found" and "nothing was looked for" are different lines in the log.
2. **Reserved documentation domains are left alone** (RFC 2606's four TLDs and
   three second-level domains, RFC 6761's `localhost`). This corpus is full of
   them on purpose; rewriting one corrupts the example and protects nobody.
3. **Role mailboxes are left alone** (RFC 2142 plus the automated senders every
   log corpus carries). `security@vendor.example` in an advisory is a published
   reporting channel — rewriting it identifies nobody better and destroys signal
   a security model should have.
4. **Everything else is pseudonymised**, unless the source is named in
   `_EMAIL_KEEP`.

`_EMAIL_KEEP` has exactly two entries and each carries its reason in the source:
`rfc`, because the IETF Trust Legal Provisions permit reproduction of an RFC *in
full* and the author block is part of the document; and `kerneldocs`, because
Author, maintainer and `Signed-off-by` lines are the kernel's Developer
Certificate of Origin record, and rewriting them does not anonymise a
contributor who signed publicly — it misrepresents who certified the
contribution. Those two sources carry roughly 72% of all address occurrences, so
this is not a rounding decision.

Everything else redacts, **including upstream material that is already public**,
for three reasons. The CC-BY and CC-BY-SA sources here satisfy attribution with
the provenance line each adapter already writes, not with an address in a
document body. A published checkpoint memorises what it is shown and cannot be
grepped afterwards, so "already public" is not the same as "safe to bake in".
And for the detection sources, where an address is sometimes an indicator of
compromise, the signal a from-scratch model needs is that a YARA rule matches on
address-shaped strings — not the exact address of a mail drop from 2019, which is
both stale and the only part that is somebody's identity.

The replacement is **not** a single literal. 8 local parts × 8 buckets = 64
placeholders under `.invalid`, chosen by `blake2b` of the address so the mapping
is stable across builds and across the forked child processes. A single
26-character literal substituted roughly 7,700 times would pass the privacy gate
while creating exactly the kind of high-frequency constant this corpus's
measured problem already consists of. 64 buckets over ~3,900 distinct addresses
puts about 60 real addresses in each: the bucket is a lossy class label, not a
fingerprint. `_check_email_policy_names` warns when a keep entry names a source
that no longer exists, because a policy for a renamed adapter is a policy nobody
is getting.

`ownrepos.py::_chokepoint_owns_addresses` asks the chokepoint whether it has
taken the job over and then **confirms it behaviourally**, by pushing a
fabricated address through `build._redacted` and checking it is gone. Anything
other than a confirmed handover fails closed: this source redacts for itself and
says so in the build log. That is the whole lesson of the twenty days, encoded.

### Layer 4 — the artifact verifier, and the build gate

Not one of the audit's findings was a bug in a substitution. Every one of them
was **the absence of a pass over the output**. `training/corpus/verify.py` is
that pass, and it is deliberately the dumbest thing in the tree: it does not
know how the corpus was built, it does not trust that anything upstream ran, and
it answers one question — *is this machine's identity in these bytes*.

- **It reads the bytes, not the in-memory documents.** That makes the ordering
  of every transform irrelevant, which is the right way to hold this invariant
  rather than by inspecting call sites.
- **It reports fingerprints, never values.** Every finding is
  `kind + len=<n> + sha256=<8 hex>`. A `Leak` has no field that can hold a
  value, and the file path in a finding is scrubbed by the same needle set,
  because this corpus lives under a volume whose name is itself a needle.
- **`Needles` is unserialisable by construction.** No `__dict__`, a `__repr__`
  and `__str__` that reveal only counts, pickling raises, `json.dumps` raises,
  no `to_json`, no `asdict`, no iteration that yields a raw string, and
  `__init__` refuses so a caller cannot assemble one from a table it read off
  disk. Every accidental way out of a Python object is closed. In-process code
  can still read the attributes and this class does not pretend otherwise — what
  it guarantees is that the path the audit actually took raises or redacts.
- **An eight-hex fingerprint is not a cryptographic secret and is not claimed
  to be.** A SHA-256 prefix of a seven-character account name is guessable by
  anybody who already knows it. What it buys is that the literal is not
  *written down*: a report, a CI log, a test fixture and a commit message can
  all name a leak, count it and group two occurrences as the same value without
  any of them becoming the next thing that has to be scrubbed.
- **An empty needle table is a failure, not a pass.** `needles.gaps()` turns the
  fail-open check on the instrument itself and names any probe that should have
  produced something on this platform and did not. `verify_corpus` returns
  leaks and does not raise — the caller decides — which is what lets the build
  gate, the CLI and the tests share one scanner instead of growing three that
  drift apart, the way `_identity_pattern` and `identity_leaks` once did.
- **Three exit codes, and the third is the point.** `0` clean, `1` leaking,
  `2` could not verify. `redact_identity`'s old fail-open collapsed 2 into 0.
- **It is calibrated.** `--calibrate` runs the detector against fixtures
  constructed before any corpus pass: 35 positives (one per kind and per
  spelling a real tool emits) and 40 negatives (the things this corpus is full
  of on purpose). `--self-test` plants a synthetic needle in a temp directory,
  proves it is found, removes it and proves the same tree comes back zero —
  because without the second half a verifier that always answers "clean" is
  indistinguishable from one that works. The CLI refuses to trust its own
  numbers (`EXIT 2`) when calibration fails.

`build.py::_verify_written` runs that scanner over the JSONL the build just
wrote and records the verdict in `CORPUS-GATE.txt` beside the data. Three things
about how it decides:

- **Nothing is deleted on a failure.** The leaking file is the evidence that
  names the adapter, and destroying it to feel safer destroys the only thing
  that identifies the bug.
- **Only `*.jsonl` findings fail the build.** A leak in anything else in the
  directory ships with the corpus but is read by nothing that trains, and
  `PROVENANCE.md` deliberately names each source's author and URL — for
  `ownrepos` that is the operator's own public handle, present as the
  attribution the MIT licence is satisfied by. A gate that refused its own
  licence record would have exactly one stable state, which is switched off.
  Those findings are reported in full and not enforced.
- **A crashed verifier fails CLOSED; a missing verifier does not.** If
  `verify_corpus` raises, the marker says `FAIL`, because "we could not check"
  has to resolve the same way as "it is dirty". If `verify.py` is not importable
  at all the build does *not* fail — a deliberate and uncomfortable exception,
  so the module is not unusable until the scanner lands — and the marker says
  `UNVERIFIED` in capitals. A table with gaps also yields `UNVERIFIED`: it
  withholds the PASS rather than failing the build, because that is a statement
  about the instrument, not about the corpus.

### Layer 5 — the corpus gate on the training side

The chokepoint only ever protected the build. `read_documents()` and
`iter_corpus()` globbed `*.jsonl` with no redaction and no check, which made the
tokenizer the widest bypass in the project: a tokenizer fitted on leaking text
keeps it as BPE merges, and `tokenizer.json` is a shipped artifact.

Two mechanisms close that now.

`build.py::read_documents` calls `_refuse_failed_gate` on the first `next()`.
It is the one door the tokenizer and the shard writer are documented to come
through, so a verdict enforced there reaches all of them.

`training/data.py::require_clean_corpus` is the real gate, and it runs before a
byte is tokenised, from `iter_corpus`, `tokenize_corpus` and the tokenizer
training entry points. It derives needles from the running system every time —
there is deliberately **no `needles` parameter**, because handing it an empty
table would verify every corpus, stamp it clean and outlive the call. It
distinguishes three answers:

- **Clean** → writes `.corpus-verified.json`, holding basenames, byte counts,
  digests, the kind names checked, a digest of the verifier's own source, and
  one digest naming the needle table. No needle, no path, no host name. Any
  change to `verify.py` invalidates every stamp written by the old one without
  anybody bumping a version, and a changed needle table — a volume mounted, an
  address renewed — does the same.
- **Leaking** → `CorpusLeakError`, with an escape hatch that is deliberately the
  most awkward affordance that is still usable. `accept_leaking_corpus` takes
  the `leak_token` of the leaks found *right now*: not a boolean, not read from
  the environment or any config file, invalidated the moment the corpus changes
  so it cannot be parked in `overnight.sh`, and obtainable only by running the
  scan and reading the refusal. It is not called `--force`, because `--force` is
  a word people type. He has to be able to work on a corpus he knows is dirty
  while fixing it; a gate that cannot be worked with gets patched out, and a
  patched-out gate protects nothing.
- **Clean from a blind instrument** → `CorpusUnverifiable`, and **this one has
  no override at all.** A corpus the verifier could not fully check is not
  something anybody should be able to wave through, because the leak refusal at
  least names what it found and this would name nothing.

The acceptance is re-stated downstream. `tokenize_corpus` writes what the gate
said into `index.json` — including the **resolved** path, so a shard set built
from `clean-v8` records that it read `clean-v7`'s bytes — and
`_check_shard_provenance` refuses shards whose own index says the corpus behind
them leaked. Without that, the shards launder the acceptance: tokenise once with
`accept_leaking_corpus` and every later run reads `*.bin` and asks nothing. The
permission has to be re-stated at the point where the leak would reach a model,
and the token cannot be re-derived from shards, because tokens are not
greppable — which is the whole reason the gate exists.

### Refusal semantics: a refusal discards the whole source

When `redact_identity` raises, `build.py` converts it to `_RedactionRefused` —
its own exception type, not the `except Exception` that reported it as `parse
failed` — and **discards the entire source**. Not the document. Not the
documents after it. The whole source: `collected` is never assigned, no file is
written, any file a previous build left behind is removed and named, and the
source's counts are zeroed so they cannot survive into the report.

The reason is the blast radius. The earlier version wrapped the document loop
while appending to `kept` inside it and assigning `collected[spec.name] = kept`
unconditionally afterwards, so a refusal **truncated the source and wrote every
prior document to disk** — documents that came out of the same adapter and the
same walk as the one caught leaking. The surviving prefix is not neutral
material that happened to come first; it came from the same leaking adapter, and
there is no argument that the leak started at the document that got caught.
`_source_documents` in the same file already stated the correct standard:

> Skipped and named is honest; truncated and counted is not.

A refusal is also a different *instruction* from a timeout, which is why it gets
its own list in the build summary. A timeout says re-run. A redaction refusal
says an adapter in this tree is handing the chokepoint text carrying this
machine's identity, and it will refuse again, identically, forever, until that
adapter is fixed.

Any exception out of the redactor becomes a refusal, not just the documented
`RuntimeError`: if the substitution raised `KeyError` on a case-fold the table
does not hold, we equally do not know the document is clean, and "we do not
know" resolves the same way as "it is dirty". The refusal crosses the
parent/child process boundary as the exception class's own name, derived rather
than retyped, so a rename cannot silently turn a refusal back into a parse
failure.

---

## 3. What these defences cannot reach

An honest limits section is worth more than a confident one. Nothing below is a
hypothetical; each one is a specific thing the code in this tree does not do.

**A derived display name is only caught when it contains a literal the table
already holds.** macOS `ComputerName` is usually `<account>'s MacBook Pro`, so
it rides along with the account name — on this machine. A machine renamed by
hand is a string the table was never told and cannot invent.

**Another local account's real name is not reachable.** `enum.users` enumerates
every local account and reports a `real_name` for each; the table reads the
GECOS field of **this** uid only.

**A git-configured legal name is detected but never substituted.** The identity
table does not read `git config user.name` at all. `verify.py::_git_identities`
does, so the verifier will flag it and the gate will refuse the corpus — but no
redactor in this tree will remove it. The asymmetry is deliberate in the
verifier (it may annoy, it may not miss) and unaddressed in the substituter.

**A person's name in prose is not patternable the way an address is.** "Thanks
to Jane Roe for the review" has no heading and no entry structure for
`_roster_section` to key on; nor does a roster introduced by bold text or a
table; nor a mononym, a lowercase family name, a name in a non-Latin script, or
a handle that is somebody's real name. Conversely, two capitalised words that
are neither an organisation nor a person will drop a document. The honest
consequence is that `ownrepos` remains **the one source that needs a human to
look at what it collects**, and that is also why its policy excludes rather than
edits: an exclusion that fires on the wrong document loses a README, while a
scrub that misses a name publishes it.

**A literal cut in half by truncation is not matched.** Redaction runs on the
rendered document, and `whetstone/kernel/render.py`'s `MAX_VALUE` truncates a
value at 220 characters, so `/Users/<name>` can survive as a partial path no
table entry matches. It is not fixable at the other end: the runtime
deliberately does not import anything under `training/`. What makes it tolerable
is arithmetic plus a measurement — the longest literal on this machine is 62
characters, so a straddle needs 158 characters of prefix before it, and a scan
of the built cache found none. If that stops being true, the answer is to
substitute the truncated spellings too, not to widen what counts as clean.

**A four-character floor is a deliberate hole.** A three-character account name
occurs inside unrelated package names, service names and paths, and substituting
it would rewrite all of those with no way to tell afterwards which were which.
A host with a three-character name is not protected, by choice.

**`ipv4-private` findings are ambiguous by construction**, and the verifier says
so in its own report. An RFC1918 address bound on this host is also a
documentation example in RFC, nuclei and Sigma text, and the two are the same
bytes. Treat them as a prompt to look, not as a leak, and gate on the kinds that
actually identify a machine.

**A refusal message can carry a value, and a build log can keep it.** This is
the sharpest remaining gap and the comment in `build.py::_scrubbed` is wrong
about it. That comment says the refusal "name[s] the surviving FORM (a table key
such as 'the home path'), never a value". It does not:
`identity_leaks` returns the matched **literals**, and `redact_identity`
interpolates that list into its `RuntimeError`. Verified with a synthetic table
in this repository — the message contained the planted literal and contained no
table-key phrase. The same shape is in `lab/capture.py::_write_redacted`. That
message then flows into `_RedactionRefused`, into `BuildStats.error`, into
`balance_report`'s "sources that failed" block, and onto stdout — which
`scripts/overnight.sh` redirects into a per-stage log file on disk. The branch is
designed to be unreachable (`_assign` and the cross-pair guard exist to make it
so) and has never fired, but *unreachable* and *safe when reached* are different
properties, and only one of them is implemented. **Treat any build log
containing `REDACTION REFUSED` as a file that may hold a cleartext identifier.**

**Unredacted text is written to a temp file before the chokepoint sees it.** The
per-source watchdog runs each adapter in a child process which writes its full
document set to a `mkdtemp` transport file. The child redacts before writing —
which is why a refusal can happen over there and has to cross the process
boundary — but the scratch directory is still the one place on this machine where
a source's text exists before any gate has seen it.

**An absent gate marker is not a refusal.** `_refuse_failed_gate` reads the
first line of `CORPUS-GATE.txt` and `return`s silently on `OSError`. It refuses a
directory whose last build **failed**; it permits a directory that was never
gated at all. As of this writing **no `CORPUS-GATE.txt` exists anywhere under
`data/corpus/`**, so every generation on disk is in exactly that state. The
`require_clean_corpus` gate in Layer 5 is what actually covers them, and it is
the one to rely on.

**A shard set with no provenance record gets a warning, not a refusal.**
`_check_shard_provenance` refuses shards whose index records an accepted leak,
but a shard set written before the record existed has nothing to refuse over,
and refusing it would make every existing shard set unusable and the gate the
first thing patched out. Every `tokenized-*/index.json` on disk today is in that
category: `provenance_report()` answers that it "records no corpus provenance",
which is a *different statement* from verified and must not be read as one.

---

## 4. Third parties

The corpus contained the full names and personal addresses of people who are not
the operator — in one case a university group project README naming its whole
team by name, role and personal `.edu` address under a course code. Those people
never agreed to appear in a published model's training data, and nobody asked
them.

**The policy: material identifying a non-consenting third party is excluded, not
scrubbed, and its removal is not a judgement call.** There is no balancing test
here, no "it is already public", no "it is only a few documents". The addresses
were never the thing that identified anyone — they were the part that happened to
be patternable. Delete four addresses from that README and four full names
remain, each against a named role, under a named course code, in a document
whose subject is that those four people built this: a reader reconstructs the
roster from what is left, and a model trained on it has learned the association
regardless. A half-scrubbed document is worse than either choice, because it
*looks* handled.

This document deliberately does not name the repository or the file. The
abstraction level in `ownrepos.py` — "a four-person university group project
README" — is the right one, and a privacy document that points at the data is a
pointer somebody will follow.

The operator's own data is a different question with a different answer: he can
publish his own address whenever he likes, and that is exactly why rule 1 of the
email policy has no exception. He can un-publish a web page. He cannot
un-publish a checkpoint.

---

## 5. The publication rule

> **No checkpoint trained on an unverified generation may be published.**

This is a rule with a check attached, not an aspiration. The check is:

```bash
python3 -c "
from pathlib import Path
from training.data import ShardIndex
print(ShardIndex.load(Path('data/corpus/<tokenized-generation>')).provenance_report())
"
```

Three possible answers, and only one of them permits publication:

| What it prints | What it means | Publish? |
|---|---|---|
| `verified  yes` for every root | the corpus gate scanned those bytes with a needle table that was not blind | yes |
| `verified  NO (<n> leaks)` | somebody minted a `leak_token` and tokenised anyway; those values are in the weights | **no** |
| `records no corpus provenance` | the shard set predates the record; nothing can say what it read or whether anything checked it | **no** |

The third row is the one that matters most right now, because **every shard set
on disk is in it**, and a warning is not a verdict. "I verified v8" was once a
sentence about v7's bytes, and the only honest thing a tool can do about that is
resolve the symlink and say which name it actually read — which `Survey`,
`CorpusProvenance` and `ShardIndex` all now do.

Two corollaries:

- **A quarantine is not a publication decision.** `scripts/quarantine_corpus.py`
  will not touch `models/`, deliberately: a model file is not a corpus
  generation, and letting a move imply a publication verdict would conflate
  them. The rule above is what covers the checkpoints; the move is what stops
  somebody training on a contaminated generation at 2am.
- **A clean scan is not a clean verdict.** The scanner reports what it found; it
  cannot report what it was never able to look for. A sampled scan has seen a
  fraction of the bytes, a fallback needle set may have no email layer, and a
  tokenizer shard is token ids with no text in it at all. A generation with zero
  hits is still quarantined when it predates the youngest redaction fix — on
  provenance, labelled as provenance, and never dressed up as a measurement.

---

## 6. Pre-publication checklist

Run in this order. Each step says what it proves, and a step that fails stops
the sequence — the next step's answer is not meaningful without it.

```bash
# 0. The instrument, before the measurement. Three measurement bugs in this
#    project each accused the model and all three were in the ruler.
python3 -m training.corpus.verify --calibrate
python3 -m training.corpus.verify --self-test
```
Proves the detector finds what it should (recall against constructed positives),
does not fire on what this corpus contains on purpose (precision against
constructed negatives), and **bites in both directions** — a planted needle is
found, and the same tree without it comes back zero. A `--calibrate` failure
means every number below is untrustworthy, and the CLI itself will exit 2 rather
than report them.

```bash
# 1. Both suites.
python3 -m pytest
```
Proves the invariants have not regressed: that no field of a `Leak` can contain
a needle, that `Needles` refuses every serialisation path, that `_redacted`
covers `ident`, that a refusal discards the whole source, and that the
substituter and the verifier read the same table.

```bash
# 2. What is actually on disk, and which names are one artifact.
python3 scripts/quarantine_corpus.py            # dry run; --apply to perform
```
Proves which generations predate the youngest redaction fix, resolves every
symlink and reports what it really points at, and prints the exact `mv` and
`ln -sfn` to undo the whole plan. It moves and never deletes; there is no
`unlink` and no `rmtree` in the file, and a cross-device move is refused rather
than silently performed as copy-then-delete. **The data is his; destroying it is
his decision, not a script's.**

```bash
# 3. The generation you intend to train on, scanned byte by byte.
python3 -m training.corpus.verify data/corpus/<generation>; echo "exit=$?"
```
Proves whether this machine's identifiers are in those bytes. Read the exit code,
not the prose: `0` clean, `1` leaking, `2` could not verify. Check the `probes:`
line and any `table is THIN` warning before believing a `0` — a verifier with an
empty table also prints a reassuring number.

```bash
# 4. The build, if you are rebuilding.
python3 -m training.corpus.build --out data/corpus/<generation> --cache data/corpus/raw
```
The preflight proves the redactor imports and has a non-empty table *before any
fetching*, the per-source email table proves the pass ran and shows what it did
on this run, and `_verify_written` reads the output back and writes
`CORPUS-GATE.txt`. Require `PASS`. `UNVERIFIED` means the scanner could not be
imported or the needle table had gaps — that is a statement about the
instrument, and it withholds the PASS for a reason.

```bash
# 5. The shard set behind the checkpoint.
python3 -c "
from pathlib import Path
from training.data import ShardIndex
print(ShardIndex.load(Path('data/corpus/<tokenized-generation>')).provenance_report())
"
```
Proves which corpus these shards read (resolved, not as typed), its content
digest, and whether anything vouched for it. Apply the table in §5.

```bash
# 6. Last: anything else that is about to be published alongside.
python3 -m training.corpus.verify examples/runs; echo "exit=$?"
```
`examples/runs/` is public and is written by `lab/capture.py`, which redacts and
then asks `identity_leaks` again before writing. The second ask cannot catch
anything the first missed — it is there so the question keeps being asked if
somebody later swaps the substitution for something cleverer.

**What is not on this list, and should be.** Nothing in this tree scans for
credentials. The audit that prompted all of this was the first look, found
nothing requiring rotation, and that result is about one point in time, not about
the build. If a future adapter sweeps up a key, no gate here will notice.

---

## 7. How this was found

Eight agents were pointed at a built corpus — 208,346 documents, 625 MB, 47
JSONL files — because the operator asked to be sure the training data leaked
nothing private *before* he trained and published. Several analyst claims were
refuted by the verifiers, which is the half of a multi-agent review worth having.

The good result is real and worth stating: **nothing required rotation.** No
credential-shaped value survived calibration; the geolocation category, hardware
serials, platform UUIDs and phone numbers were clean. What was there instead was
live network identity the identity table had no layer for at all, and
third-party personal data in one source.

The findings that mattered more than any single leak were structural. There are
five, and all five are in the module docstring of `training/corpus/verify.py`,
in order of how little code each one needed to catch:

1. An email redactor landed twenty days **after** the artifact it was meant to
   protect. From the source tree alone, a redactor that was added and never run
   is indistinguishable from one that ran and found nothing.
2. `clean-v8` is a symlink to `clean-v7`, so "v8 was verified" was a statement
   about v7's bytes, and nothing in the build said so.
3. A redaction refusal truncated the source, wrote every earlier document to
   disk, and labelled it `parse failed`.
4. `redact_identity`'s fail-open was reachable: an empty table returned
   Mac-captured text unchanged and silently. One analyst declined this as
   unreachable; a verifier proved it.
5. Nothing between the chokepoint and the weights looked again. The chokepoint
   only protected the build.

Not one of those is a bug in a substitution. Every one is the absence of a pass
over the output, which is why Layers 4 and 5 exist and why they read bytes rather
than inspect call sites.

A sixth finding was a measurement, not a bug, and it changed the design:
`trajectories.jsonl` is 79% structure and 21% this-one-Mac, but that 21% is 253
distinct literals repeated a mean 947 times each, about 89% of which appear
nowhere else in 625 MB. The percentage *hides* the memorisation hazard. That is
where "privacy and generalisation are one pass and two problems" comes from, and
why no replacement in this tree is a single token.

### The lesson: the audit itself leaked

Six of the audit's own working files wrote live MAC addresses, global IPv6
addresses and an email address to disk as cleartext literals while the reports
claimed they had not. **Both independent verifiers made that their single most
important finding.** Those files were deleted and the directory re-scanned
clean.

That is not carelessness. It is the default behaviour of every convenience in
the language: `repr`, `json.dumps`, `pickle`, a dataclass's generated
`__repr__`, an f-string in a log line, a pytest assertion message. The next
person needs to know that **handling this data is where the hazard is**, not
just the corpus — and that the standing rules below are not ceremony:

- Derive every needle at runtime from the OS. Never configure one, never persist
  one. A configured list is a list of the leaks somebody already noticed; a
  persisted list is a new leak with a filename.
- A needle table must be structurally unserialisable, with `__repr__` and
  `__str__` that reveal nothing. `Needles` is the worked example.
- Report `kind + length + sha256 prefix`. Never a value. Vigil's keystone
  property — it never prints a full secret — is the same property, and
  `verify.py` is the corpus side of it.
- Test fixtures are synthetic only: `2001:db8::/32` and `3fff::/20` for
  addresses, `00:00:5e:00:53:xx` for MACs, `@example.invalid` for mail.
- And **verify an RFC boundary with `ipaddress`, never from memory.** One
  fixture in this project used `3fff:1234::1` as a "documentation address".
  `3fff::/20` fixes the top four bits of the second hextet at zero, so the block
  runs `3fff::` to `3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff` and anything from
  `3fff:1000::` up is ordinary global unicast:

  ```python
  >>> import ipaddress
  >>> ipaddress.ip_address('3fff:1234::1') in ipaddress.ip_network('3fff::/20')
  False
  ```

  The classifier was right and the fixture was wrong — and in the code it read
  exactly like a false positive, which is the most expensive way for a detector
  to be correct.

---

## Where each thing lives

| Concern | File |
|---|---|
| The chokepoint, email policy, build gate | `training/corpus/build.py` |
| The identity table, substituter, leak check | `training/trajectories.py` |
| The artifact verifier, needles, calibration | `training/corpus/verify.py` |
| The training-side gate, stamp, shard provenance | `training/data.py` |
| Source-level exclusion and the handover check | `training/corpus/sources/ownrepos.py` |
| Public run capture | `lab/capture.py` |
| Moving contaminated generations aside | `scripts/quarantine_corpus.py` |
| Regenerating trajectories off this machine | `scripts/regenerate_trajectories.py` |

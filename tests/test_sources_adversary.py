"""Tests for the ADVERSARY-family sources: atlas, engage, mispgalaxy, d3fend, attackflow.

Every test here exists because of a specific way one of these five adapters
could be wrong *and still produce a corpus*. That is the failure mode the
corpus layer has: a bad gate rule raises, a bad adapter just trains a slightly
worse model and nobody finds out for four steps.

Three groups of them, and the grouping is the argument:

**The parser tests.** ``d3fend`` ships a hand-written Turtle subset parser
because rdflib is not a dependency, and ``attackflow`` recovers a graph through
four levels of an editor's layout model. Both of those are the kind of code that
returns *something* when it has regressed. The tests feed them the exact
constructs that break the obvious implementation: a triple-quoted literal whose
markdown contains lines starting with ``###`` and ``:``, a prefixed name with a
dot in it, a statement whose subject is a blank node, an ``owl:unionOf``
collection — and, for attackflow, a drawn line whose endpoints can only be found
by walking latch to anchor to owner.

**The privacy tests.** The corpus privacy audit found 23,535 occurrences of 11
values in a shipped corpus, and then found that the verifier built to catch
that had reported "0 leaks" having read zero bytes. So these do not test that a
scrubber exists; they test that it fires, that it fires on the *rendered*
document rather than on the fields the adapter remembered to check, that the
ceilings refuse rather than quietly discarding, and that nothing reports a
finding by quoting it.

**The duplication tests.** Four of these five sources sit beside an existing
source reading the same upstream family. The tests pin the specific exclusions:
``d3fend`` must never emit the ATT&CK and ATLAS classes embedded in its
ontology, ``mispgalaxy`` must never read a ``mitre-*`` cluster file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from training.corpus.source import Document, Register, Side, SourceError, normalise

pytest.importorskip("yaml", reason="atlas reads ATLAS.yaml")

from training.corpus.sources import (  # noqa: E402 - after importorskip
    atlas,
    attackflow,
    d3fend,
    engage,
    mispgalaxy,
)

#: The real caches, when this machine has them. The cache-backed tests are the
#: only ones that can check "does the whole adapter still agree with upstream",
#: and they skip rather than fail on a machine that has never fetched — a test
#: that needs 10 MB of network to pass is a test that gets deleted.
_CACHE = Path(__file__).resolve().parents[1] / "data" / "corpus" / "raw"

_FAMILY = (atlas, engage, mispgalaxy, d3fend, attackflow)


def _cached(name: str) -> Path:
    path = _CACHE / name
    if not path.is_dir():
        pytest.skip(f"no {name} cache; run the build once to populate it")
    return path


# --------------------------------------------------------------------- contract


class TestFamilyContract:
    """What all five must declare, whatever else they do."""

    def test_each_declares_a_licence_naming_its_upstream_file(self):
        """A licence claim that cannot be checked against a file is a guess.

        ``gtfobins`` is GPL-3.0 and not MIT, ``sigma`` is DRL-1.1 and not MIT.
        The convention that caught both is that the declaration quotes the
        upstream's own LICENSE and says where it was read from, so the next
        reader can check it in one command instead of trusting a badge.
        """
        for module in _FAMILY:
            licence = module.SPEC.license
            assert licence.strip(), module.SPEC.name
            assert "LICENSE" in licence or "licenses/" in licence, module.SPEC.name
            assert "http" in licence, module.SPEC.name

    def test_each_copies_its_licence_into_the_cache(self):
        """The declaration names a path under licenses/; the fetch must write it."""
        for module in _FAMILY:
            assert "licenses/" in module.SPEC.license, module.SPEC.name

    def test_registers_and_sides_are_declared(self):
        for module in _FAMILY:
            assert isinstance(module.SPEC.register, Register), module.SPEC.name
            assert isinstance(module.SPEC.side, Side), module.SPEC.name

    def test_the_family_is_adversary_register(self):
        """The whole point of the family: the register report said 9% vs 11%."""
        for module in _FAMILY:
            assert module.SPEC.register is Register.ADVERSARY, module.SPEC.name

    def test_no_source_in_this_family_is_named_after_an_existing_one(self):
        """A name collision would make --only and the provenance table lie."""
        from training.corpus.build import discover_sources

        names = [spec.name for spec in discover_sources()]
        assert len(names) == len(set(names)), "duplicate source names discovered"
        for module in _FAMILY:
            assert names.count(module.SPEC.name) == 1, module.SPEC.name

    def test_privacy_patterns_are_identical_across_the_family(self):
        """A check that differs per adapter is a check with no stateable guarantee.

        Each module carries its own copy — a private helper shared between
        sources is how one of them quietly drifts — so the property that matters
        is that the copies have not diverged.
        """
        emails = {module._EMAIL.pattern for module in _FAMILY}
        handles = {module._HANDLE.pattern for module in _FAMILY}
        assert len(emails) == 1, f"email patterns have diverged: {emails}"
        assert len(handles) == 1, f"handle patterns have diverged: {handles}"

    @pytest.mark.parametrize("sample", [
        "contact me at analyst.name@example.org for details",
        "reach out: a@b.co",
        "mailto chain ends at first.last+tag@sub.domain.example",
    ])
    def test_the_email_pattern_matches_the_shapes_that_leaked(self, sample):
        assert atlas._EMAIL.search(sample), sample

    @pytest.mark.parametrize("sample", [
        "run user@host:/path/file",                 # scp target
        "an email first.last@example.com",          # caught by _EMAIL, not here
        "the @decorator form",                      # python, not a handle
        "@reboot /usr/local/bin/agent",             # crontab, not a handle
        "@property on the accessor",                # python, not a handle
        "@media screen and (min-width: 40em)",      # CSS, not a handle
        "see @param and @returns in the docblock",  # javadoc, not a handle
    ])
    def test_the_handle_pattern_does_not_fire_on_lookalikes(self, sample):
        """A handle pattern that eats crontab lines would fail builds.

        Precision matters in both directions here, because this family's filters
        DROP or REFUSE on a hit: a false positive deletes corpus content or
        stops a build, and a false negative ships somebody's contact details.
        This test is the reason the pattern has an allowlist at all — asked what
        it did to ``the @decorator form``, the first version flagged it.
        """
        assert not atlas._HANDLE.search(sample), sample

    @pytest.mark.parametrize("sample", [
        "hat tip to @someresearcher for the sample",
        "first reported by @vendorlabs",
    ])
    def test_a_real_handle_is_still_flagged(self, sample):
        """The allowlist must not have turned the filter off.

        Crediting a researcher by handle is the normal way threat-intelligence
        prose names a person, so this is the case the filter exists for.
        """
        assert atlas._HANDLE.search(sample), sample

    def test_a_finding_is_reported_as_a_hash_never_as_the_value(self):
        """The audit's own verifier printed the leaks it found. Not again."""
        for module in _FAMILY:
            digest = module._short_hash("analyst@example.org")
            assert len(digest) == 8
            assert "@" not in digest and "example" not in digest


# ------------------------------------------------------------------------ atlas


_ATLAS_BUNDLE = {
    "id": "ATLAS",
    "version": "test",
    "matrices": [{
        "id": "ATLAS",
        "name": "ATLAS Matrix",
        "tactics": [{
            "id": "AML.TA0002", "name": "Reconnaissance",
            "object-type": "tactic",
            "description": "The adversary is trying to gather information "
                           "about the AI system they can use to plan future "
                           "operations, which is a long enough sentence to "
                           "clear the character floor comfortably.",
        }],
        "techniques": [{
            "id": "AML.T0000", "name": "Search Open Technical Databases",
            "object-type": "technique",
            "description": "Adversaries may search for publicly available "
                           "research and technical documentation to learn how "
                           "and where AI is used within a victim organization, "
                           "stated at length so the floor is cleared.",
            "tactics": ["AML.TA0002"],
            "ATT&CK-reference": {"id": "T1596", "name": "Search Open "
                                                        "Technical Databases"},
            "maturity": "demonstrated",
        }, {
            "id": "AML.T0000.001", "name": "Pre-Print Repositories",
            "object-type": "technique",
            "description": "Adversaries may search pre-print repositories for "
                           "technical details, which is again long enough to "
                           "be emitted rather than skipped by the floor.",
            "specializes": "AML.T0000",
        }],
        "mitigations": [{
            "id": "AML.M0000", "name": "Limit Public Release of Information",
            "object-type": "mitigation",
            "category": "policy", "ml-lifecycle": ["Business Understanding"],
            "description": "Limit the public release of technical information "
                           "about the AI stack used in an organization's "
                           "products or services, stated long enough to pass.",
            "techniques": [{"id": "AML.T0000",
                            "use": "Limit the connection between publicly "
                                   "disclosed approaches and production."}],
        }],
    }],
    "case-studies": [{
        "id": "AML.CS0000", "name": "Evasion of a Deep Learning Detector",
        "object-type": "case-study",
        "summary": "A research team tested a deep learning model for malware "
                   "command and control traffic detection, which is a summary "
                   "long enough to clear the floor on its own.",
        "incident-date": "2020-01-01", "actor": "An AI research team",
        "target": "A production model", "case-study-type": "exercise",
        "procedure": [
            {"tactic": "AML.TA0002", "technique": "AML.T0000",
             "description": "They identified a representative approach from a "
                            "published paper."},
            {"tactic": "AML.TA0002", "technique": "AML.T0000.001",
             "description": "They pulled the paper from a pre-print server."},
        ],
    }],
}


def _atlas_cache(tmp_path: Path, bundle: dict | None = None) -> Path:
    import yaml

    path = tmp_path / atlas._DATA
    path.write_text(yaml.safe_dump(bundle or _ATLAS_BUNDLE), encoding="utf-8")
    return path


class TestAtlas:
    def test_emits_every_object_kind(self, tmp_path):
        docs = list(atlas._documents(_atlas_cache(tmp_path)))
        kinds = {d.ident.split("/")[0] for d in docs}
        assert kinds == {"tactic", "technique", "mitigation", "case-study"}

    def test_the_tactic_carries_its_technique_membership(self, tmp_path):
        """A tactic document is the only place the whole membership co-occurs."""
        docs = {d.ident: d.text for d in atlas._documents(_atlas_cache(tmp_path))}
        tactic = docs["tactic/AML.TA0002"]
        assert "AML.T0000 Search Open Technical Databases" in tactic

    def test_a_technique_names_its_mitigation_and_its_case_study(self, tmp_path):
        """The relationship hop attack.py spent 846 documents not taking."""
        docs = {d.ident: d.text for d in atlas._documents(_atlas_cache(tmp_path))}
        technique = docs["technique/AML.T0000"]
        assert "AML.M0000 Limit Public Release of Information" in technique
        assert "AML.CS0000" in technique
        assert "T1596" in technique, "the ATT&CK cross-reference is the bridge"
        assert "AML.T0000.001 Pre-Print Repositories" in technique

    def test_procedure_steps_keep_their_order_and_their_numbers(self, tmp_path):
        """A procedure is a sequence; rendering it unordered destroys the signal."""
        docs = {d.ident: d.text for d in atlas._documents(_atlas_cache(tmp_path))}
        study = docs["case-study/AML.CS0000"]
        first = study.index("1. ")
        second = study.index("2. ")
        assert first < second
        assert study.index("representative approach") < study.index("pre-print server")

    def test_the_path_form_is_relative_because_the_site_is_a_spa(self, tmp_path):
        """atlas.mitre.org answers 404 for every deep path. No invented URLs."""
        docs = {d.ident: d.text for d in atlas._documents(_atlas_cache(tmp_path))}
        technique = docs["technique/AML.T0000"]
        assert "ATLAS path: /techniques/AML.T0000" in technique
        assert "https://atlas.mitre.org/techniques" not in technique

    def test_mitigations_are_marked_blue(self, tmp_path):
        docs = {d.ident: d for d in atlas._documents(_atlas_cache(tmp_path))}
        assert docs["mitigation/AML.M0000"].side is Side.BLUE
        assert docs["technique/AML.T0000"].side is Side.RED

    def test_an_email_in_upstream_prose_refuses_rather_than_being_stripped(
            self, tmp_path):
        """A silent strip means nobody learns upstream started carrying them."""
        bundle = json.loads(json.dumps(_ATLAS_BUNDLE))
        bundle["case-studies"][0]["summary"] += " Contact leak@example.org."
        with pytest.raises(SourceError) as excinfo:
            list(atlas._documents(_atlas_cache(tmp_path, bundle)))
        message = str(excinfo.value)
        assert "AML.CS0000" in message
        assert "leak@example.org" not in message, "the refusal must not quote it"
        assert "sha256[:8]=" in message

    def test_a_bundle_with_no_matrices_is_refused(self, tmp_path):
        with pytest.raises(SourceError):
            list(atlas._documents(_atlas_cache(tmp_path, {"id": "x"})))

    def test_ordering_is_stable_across_runs(self, tmp_path):
        cache = _atlas_cache(tmp_path)
        first = [d.ident for d in atlas._documents(cache)]
        second = [d.ident for d in atlas._documents(cache)]
        assert first == second

    def test_the_attack_reference_reads_a_list_as_well_as_an_object(self, tmp_path):
        """A single-object field that becomes a list is how upstreams grow."""
        bundle = json.loads(json.dumps(_ATLAS_BUNDLE))
        bundle["matrices"][0]["techniques"][0]["ATT&CK-reference"] = [
            {"id": "T1596", "name": "Search Open Technical Databases"},
            {"id": "T1593", "name": "Search Open Websites"},
        ]
        docs = {d.ident: d.text
                for d in atlas._documents(_atlas_cache(tmp_path, bundle))}
        assert "T1596" in docs["technique/AML.T0000"]
        assert "T1593" in docs["technique/AML.T0000"]


# ----------------------------------------------------------------------- engage


def _engage_cache(tmp_path: Path, **overrides) -> Path:
    files = {
        "goals.json": [{"id": "EGO0001", "name": "Expose",
                        "description": "Reveal the presence of ongoing "
                                       "adversary operations.",
                        "long_description": "Expose is about discovering "
                                            "previously undetected "
                                            "adversaries.<br><br>It has two "
                                            "halves and this sentence makes "
                                            "the document long enough."}],
        "goal_details.json": {"EGO0001": {"approaches": ["EAP0001"]}},
        "approaches.json": [{"id": "EAP0001", "name": "Collect",
                             "description": "Gather adversary tools and "
                                            "observe tactics.",
                             "long_description": "Collection activities are "
                                                 "used to gather information "
                                                 "about an adversary or their "
                                                 "activities at length."}],
        "approach_details.json": {"EAP0001": {"type": "Engagement",
                                              "goals": ["EGO0001"],
                                              "activities": ["EAC0001"]}},
        "activities.json": [{"id": "EAC0001", "name": "API Monitoring",
                             "description": "Monitor local APIs that might be "
                                            "used by adversary tools.",
                             "long_description": "API Monitoring involves "
                                                 "capturing an internal OS "
                                                 "function for its usage, "
                                                 "arguments and result."}],
        "activity_details.json": {"EAC0001": {
            "type": "Engagement", "goals": ["EGO0001"],
            "vulnerabilities": [{"id": "EAV0001",
                                 "eav": "When adversaries interact with the "
                                        "environment they are vulnerable when "
                                        "they collect or manipulate system "
                                        "artifacts."}],
            "attack_techniques": [{"id": "T1007",
                                   "name": "System Service Discovery",
                                   "attack_tactics": ["discovery"]}],
        }},
        "attack_mapping.json": [{"attack_id": "T1007",
                                 "attack_technique": "System Service Discovery",
                                 "eav_id": "EAV0001",
                                 "eav": "When adversaries interact with the "
                                        "environment they are vulnerable when "
                                        "they collect or manipulate system "
                                        "artifacts.",
                                 "eac": "API Monitoring",
                                 "eac_id": "EAC0001"}],
        "attack_tactics_techniques.json": {"T1007": {
            "attack_technique": {"id": "T1007",
                                 "name": "System Service Discovery",
                                 "attack_tactics": ["discovery"]},
            "attack_tactics": [{"id": "TA0007", "name": "Discovery"}],
        }},
        "references.json": [{"id": "REF0002", "activity_id": "EAC0001",
                             "title": "A paper about deception defence",
                             "url": "https://doi.example/10.1145"}],
    }
    files.update(overrides)
    for name, payload in files.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


class TestEngage:
    def test_emits_goals_approaches_activities_and_vulnerabilities(self, tmp_path):
        docs = list(engage._documents(_engage_cache(tmp_path)))
        kinds = {d.ident.split("/")[0] for d in docs}
        assert kinds == {"goal", "approach", "activity", "vulnerability"}

    def test_an_activity_carries_the_attack_techniques_it_engages(self, tmp_path):
        """The adjacency: a defensive id beside an offensive id beside prose."""
        docs = {d.ident: d.text for d in engage._documents(_engage_cache(tmp_path))}
        activity = docs["activity/EAC0001"]
        assert "T1007 System Service Discovery (Discovery)" in activity
        assert "EAV0001" in activity

    def test_the_vulnerability_document_is_the_eav_side_of_the_mapping(
            self, tmp_path):
        """Rendered EAV-major, because 29 sentences across 175 techniques."""
        docs = {d.ident: d.text for d in engage._documents(_engage_cache(tmp_path))}
        vulnerability = docs["vulnerability/EAV0001"]
        assert "EAC0001 API Monitoring" in vulnerability
        assert "T1007" in vulnerability

    def test_br_becomes_a_newline(self, tmp_path):
        docs = {d.ident: d.text for d in engage._documents(_engage_cache(tmp_path))}
        assert "<br>" not in docs["goal/EGO0001"]
        assert "previously undetected" in docs["goal/EGO0001"]

    def test_unknown_markup_refuses_instead_of_a_generic_tag_strip(self):
        """A generic <[^>]+> is how a corpus loses content that looked like a tag.

        ``owasp`` keeps its tags because there they are XSS payloads. Here the
        measured truth is that only <br> appears, so anything else is a change
        worth stopping for.
        """
        with pytest.raises(SourceError) as excinfo:
            engage._detagged("text with <a href='x'>a link</a>", "EAC0001")
        assert "generic tag regex" in str(excinfo.value)

    def test_br_variants_are_all_handled(self):
        for form in ("<br>", "<br/>", "<br />", "<BR>", "< br >"):
            assert engage._detagged(f"a{form}b", "x") == "a\nb"

    def test_a_missing_file_refuses_rather_than_thinning_the_corpus(self, tmp_path):
        cache = _engage_cache(tmp_path)
        (cache / "attack_mapping.json").unlink()
        with pytest.raises(SourceError) as excinfo:
            list(engage._documents(cache))
        assert "attack_mapping.json" in str(excinfo.value)

    def test_an_empty_activity_catalogue_refuses(self, tmp_path):
        cache = _engage_cache(tmp_path, **{"activities.json": []})
        with pytest.raises(SourceError):
            list(engage._documents(cache))

    def test_everything_is_blue(self, tmp_path):
        for doc in engage._documents(_engage_cache(tmp_path)):
            assert doc.side is Side.BLUE, doc.ident


# ------------------------------------------------------------------- mispgalaxy


def _misp_cache(tmp_path: Path, **per_file) -> Path:
    for cluster in mispgalaxy._CLUSTERS:
        payload = per_file.get(cluster.key) or {
            "name": cluster.label, "authors": ["A Maintainer"],
            "values": [],
        }
        (tmp_path / cluster.file).write_text(json.dumps(payload),
                                             encoding="utf-8")
    return tmp_path


_ACTOR = {
    "value": "APT20",
    "uuid": "aaaaaaaa-0000-0000-0000-000000000001",
    "description": "A targeted threat group assessed with moderate confidence "
                   "to be of one origin, which conducts espionage against "
                   "multiple industries and has operated for several years. "
                   "This description is long enough to clear the body floor "
                   "on its own, which is the point of writing it out.",
    "meta": {
        "country": "CN",
        "synonyms": ["VIOLIN PANDA"],
        "name-attribution": ["TH3Bug:e9491d3b-2174-47d6-8a15-ecec552d16ae",
                             "RIDGE CASTLE:598308b3-5475-48c6-9a2c-676fe1d2c6"],
        "refs": [f"https://example.invalid/report-{n}" for n in range(20)],
        "ransomnotes": ["Send bitcoin and mail us at attacker@example.org"],
        "links": ["http://leaksite.example.onion/"],
        "extensions": [".id-[attacker@example.org].locked"],
    },
    "related": [{"dest-uuid": "aaaaaaaa-0000-0000-0000-000000000002",
                 "type": "uses",
                 "tags": ['estimative-language:likelihood-probability='
                          '"likely"']}],
}

_TOOL = {
    "value": "SomeLoader",
    "uuid": "aaaaaaaa-0000-0000-0000-000000000002",
    "description": "A loader used by several groups, described at sufficient "
                   "length that the document clears the body floor without "
                   "help from its reference list, which is the property the "
                   "floor was changed to measure.",
    "meta": {"synonyms": ["TheLoader"], "refs": ["https://example.invalid/t"]},
}


class TestMispGalaxy:
    def test_the_cluster_selection_excludes_every_mitre_restatement(self):
        """Taking mitre-* would duplicate attack/attackactors/atlas/d3fend/engage."""
        keys = {cluster.key for cluster in mispgalaxy._CLUSTERS}
        assert not [k for k in keys if k.startswith("mitre-")]
        assert not [k for k in keys if k.startswith("tidal-")]
        assert "sigma-rules" not in keys, "would restate the sigma source"

    def test_the_selection_excludes_the_non_cyber_galaxies(self):
        keys = {cluster.key for cluster in mispgalaxy._CLUSTERS}
        for junk in ("firearms", "uavs", "ukhsa-culture-collections", "nace",
                     "naics", "cancer", "terrorist-groups"):
            assert junk not in keys

    def test_the_selection_excludes_the_label_only_galaxies(self):
        """stalkerware has 170 values and zero descriptions."""
        keys = {cluster.key for cluster in mispgalaxy._CLUSTERS}
        assert "stalkerware" not in keys
        assert "o365-exchange-techniques" not in keys

    def test_ransom_note_fields_are_not_on_the_rendered_whitelist(self):
        """Where the 236 measured email addresses live."""
        rendered = {field for field, _ in mispgalaxy._FIELDS}
        for excluded in ("ransomnotes", "ransomnotes-filenames",
                         "ransomnotes-refs", "extensions", "links", "uuid"):
            assert excluded not in rendered, excluded

    def test_a_cluster_renders_its_aliases(self, tmp_path):
        """The aliasing is the single thing this source is here for."""
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": ["Someone"],
                             "values": [_ACTOR]},
            "tool": {"name": "Tool", "authors": [], "values": [_TOOL]},
        })
        docs = {d.ident: d.text for d in mispgalaxy._documents(cache)}
        actor = docs["threat-actor/APT20"]
        assert "VIOLIN PANDA" in actor
        assert "TH3Bug" in actor and "RIDGE CASTLE" in actor

    def test_a_name_attribution_uuid_never_reaches_the_document(self, tmp_path):
        """A 36-character hex string beside an actor name teaches a hash."""
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": [],
                             "values": [_ACTOR]},
        })
        actor = next(d for d in mispgalaxy._documents(cache)).text
        assert "e9491d3b-2174-47d6-8a15-ecec552d16ae" not in actor
        assert "aaaaaaaa-0000" not in actor

    def test_contributor_names_are_never_read(self, tmp_path):
        """Every cluster file has an authors array. It is not adversary data."""
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor",
                             "authors": ["Some Maintainer"],
                             "values": [_ACTOR]},
        })
        for doc in mispgalaxy._documents(cache):
            assert "Some Maintainer" not in doc.text

    def test_a_related_edge_resolves_across_cluster_files(self, tmp_path):
        """A per-file index resolves 'similar' and silently drops 'uses'."""
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": [],
                             "values": [_ACTOR]},
            "tool": {"name": "Tool", "authors": [], "values": [_TOOL]},
        })
        actor = next(d for d in mispgalaxy._documents(cache)
                     if d.ident == "threat-actor/APT20").text
        assert "uses: SomeLoader (Adversary tool)" in actor
        assert "assessed likely" in actor

    def test_the_reference_cap_holds_and_says_what_it_cut(self, tmp_path):
        """Uncapped, reference lists were 50.9% of this source's characters."""
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": [],
                             "values": [_ACTOR]},
        })
        actor = next(d for d in mispgalaxy._documents(cache)).text
        assert actor.count("https://example.invalid/report-") == \
            mispgalaxy._REFERENCE_CAP
        assert "more published references" in actor

    def test_the_floor_is_measured_on_the_body_not_the_reference_list(self):
        """A floor a link list can satisfy is not measuring substance.

        Against the whole document the floor passed clusters whose body was 154
        characters — a name, three metadata lines and twenty URLs.
        """
        thin = {
            "value": "Thin", "uuid": "bbbbbbbb-0000-0000-0000-000000000001",
            "description": "Short.",
            "meta": {"refs": [f"https://example.invalid/a-long-report-url-{n}"
                              for n in range(20)]},
        }
        body, references = mispgalaxy._cluster_document(
            thin, mispgalaxy._CLUSTERS[0], mispgalaxy._Index({
                cluster.file: {"values": []} for cluster in mispgalaxy._CLUSTERS
            }))
        assert len(body) < mispgalaxy._MIN_BODY_CHARS
        joined = "\n".join([body] + mispgalaxy._section("References", references))
        assert len(joined) > mispgalaxy._MIN_BODY_CHARS, \
            "the whole document would have cleared the floor on URLs alone"

    def test_a_cluster_with_an_address_in_its_description_is_dropped_not_fatal(
            self, tmp_path):
        """Unlike atlas, this upstream is KNOWN to carry addresses.

        A build that dies on document 400 of 8,000 is a build nobody runs; a
        counted drop with a ceiling is the version that stays honest.
        """
        leaky = json.loads(json.dumps(_ACTOR))
        leaky["value"] = "Leaky"
        leaky["description"] += " Mail the operator at operator@example.org."
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": [],
                             "values": [_ACTOR, leaky]},
        })
        idents = {d.ident for d in mispgalaxy._documents(cache)}
        assert "threat-actor/APT20" in idents
        assert "threat-actor/Leaky" not in idents

    def test_the_drop_ceiling_refuses_when_it_is_passed(self, tmp_path, monkeypatch):
        """The ceiling is the instrument: 25 measured, refusal well below a flood."""
        monkeypatch.setattr(mispgalaxy, "_MAX_DROPPED", 1)
        values = []
        for index in range(4):
            leaky = json.loads(json.dumps(_ACTOR))
            leaky["value"] = f"Leaky{index}"
            leaky["uuid"] = f"cccccccc-0000-0000-0000-00000000000{index}"
            leaky["description"] += f" Contact op{index}@example.org."
            values.append(leaky)
        cache = _misp_cache(tmp_path, **{
            "threat-actor": {"name": "Threat Actor", "authors": [],
                             "values": values},
        })
        with pytest.raises(SourceError) as excinfo:
            list(mispgalaxy._documents(cache))
        message = str(excinfo.value)
        assert "ceiling" in message
        assert "example.org" not in message

    def test_a_missing_cluster_file_refuses(self, tmp_path):
        cache = _misp_cache(tmp_path)
        (cache / mispgalaxy._CLUSTERS[0].file).unlink()
        with pytest.raises(SourceError) as excinfo:
            list(mispgalaxy._documents(cache))
        assert mispgalaxy._CLUSTERS[0].file in str(excinfo.value)

    def test_metadata_is_read_through_every_shape_misp_uses(self):
        """The same field is a string here, a list there, an int in a third."""
        assert mispgalaxy._flat("CN") == ["CN"]
        assert mispgalaxy._flat(["CN", "RU"]) == ["CN", "RU"]
        assert mispgalaxy._flat(50) == ["50"]
        assert mispgalaxy._flat(None) == []
        assert mispgalaxy._flat([["a"], "b"]) == ["a", "b"]


# ----------------------------------------------------------------------- d3fend


#: Deliberately nasty, and every nasty part is in the real file:
#: a triple-quoted markdown literal containing lines that start with '###' and
#: with ':' and a bare '.', a prefixed name with a dot in it, an
#: ``owl:unionOf`` collection, a statement whose subject is a blank node, and a
#: ``\\"`` escape inside a literal.
_TTL = '''@prefix : <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .

### Object Properties

:analyzes a owl:ObjectProperty ;
    rdfs:label "analyzes" ;
    :definition "x analyzes y: The subject x examines the object y." .

:produces a owl:ObjectProperty ;
    rdfs:label "produces" ;
    :definition "x produces y: The subject x creates the object y as output." .

### Classes

:FileAnalysis a owl:Class,
        owl:NamedIndividual ;
    rdfs:label "File Analysis" ;
    rdfs:subClassOf :DefensiveTechnique,
        [ a owl:Restriction ;
            owl:onProperty :analyzes ;
            owl:someValuesFrom :File ],
        [ a owl:Restriction ;
            owl:onProperty :enables ;
            owl:someValuesFrom :Detect ] ;
    :d3fend-id "D3-FA" ;
    :synonym "File Inspection" ;
    :definition "File Analysis is an analytic process to determine a file's status, for example: virus, trojan, benign, malicious, trusted or unauthorized." ;
    :kb-reference :Reference-Example ;
    :kb-article """## Technique Overview
Some techniques use file signatures or file metadata to compare against
historical collections of malware.

### Considerations
A file may be compared against a source of ground truth. The sentence ends here.
:definition is a word that appears in this prose and must not be read as a predicate.""" .

:Detect a owl:Class ;
    rdfs:label "Detect" ;
    rdfs:subClassOf :DefensiveTactic ;
    :definition "The detect tactic is used to identify adversary access to or unauthorized activity on computer networks, which is a long enough definition to be emitted." .

:File a owl:Class ;
    rdfs:label "File" ;
    rdfs:subClassOf :DigitalArtifact,
        [ a owl:Restriction ;
            owl:onProperty :contains ;
            owl:someValuesFrom :FileContent ] ;
    :definition "A file is a computer resource for recording data discretely in a computer storage device, and this definition is deliberately long enough to clear the floor." .

:T1204.002 a owl:Class ;
    rdfs:label "Malicious File - ATTACK" ;
    skos:prefLabel "Malicious File" ;
    rdfs:subClassOf :OffensiveTechnique,
        [ a owl:Restriction ;
            owl:onProperty :produces ;
            owl:someValuesFrom :File ] ;
    :attack-id "T1204.002" ;
    :definition "An adversary may rely upon a user opening a malicious file in order to gain execution, and the quoted word \\"file\\" is here to exercise the escape handling." .

:AML.T0000 a owl:Class ;
    rdfs:label "Search Open Technical Databases - ATLAS" ;
    rdfs:subClassOf :OffensiveTechnique ;
    :attack-id "AML.T0000" ;
    :definition "Adversaries may search for publicly available research, and this class exists in the real ontology too, which is why it must never be emitted." .

:ActiveLearning a owl:Class,
        owl:NamedIndividual ;
    rdfs:label "Active Learning" ;
    rdfs:subClassOf :MachineLearning ;
    :d3fend-id "D3A-AL" ;
    :definition "Active learning aims to improve learning efficiency by allowing the learning algorithm to select which data to learn from, and this definition is long enough to be emitted." .

:AlethicLogic a owl:Class ;
    rdfs:label "Alethic Logic" ;
    rdfs:subClassOf :LogicalMethod ;
    :d3fend-id "D3A-AL" ;
    :definition "Alethic logic is a modal logic concerned with necessity and possibility, and upstream has given it the SAME id as Active Learning, which is the collision this fixture exists to reproduce." .

:MachineLearning a owl:Class ;
    rdfs:label "Machine Learning" ;
    rdfs:subClassOf :AnalyticTechnique ;
    :definition "Machine learning is a field of study concerned with algorithms that improve with data, stated at length so the class is described." .

:LogicalMethod a owl:Class ;
    rdfs:label "Logical Method" ;
    rdfs:subClassOf :AnalyticTechnique ;
    :definition "A logical method draws conclusions by inference rules rather than by statistics, stated at length so the class is described." .

:Reference-Example a owl:Class ;
    :kb-reference-title "A Published Paper About File Analysis" ;
    :kb-organization "An Institute" ;
    :kb-author "A Named Researcher" ;
    :kb-abstract "The abstract of somebody else's paper, quoted into MITRE's graph." .

:version a owl:DatatypeProperty ;
    rdfs:range [ a owl:DataRange ;
            owl:unionOf (
                    xsd:integer
                    xsd:string ) ] ;
    :definition "x version y: The product or service x has the version y." .

[ a owl:AllDisjointClasses ;
    owl:members ( :File :Detect ) ] .
'''


@pytest.fixture()
def ttl(tmp_path: Path) -> Path:
    path = tmp_path / d3fend._ONTOLOGY
    path.write_text(_TTL, encoding="utf-8")
    return path


class TestD3fendTurtleParser:
    """The parser is the newest and most fragile thing in this family."""

    def test_a_triple_quoted_literal_is_not_read_as_structure(self, ttl):
        """The constructs inside kb-article that break a line-oriented parser."""
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        article = subjects[":FileAnalysis"][":kb-article"][0]
        assert "### Considerations" in article
        assert ":definition is a word" in article
        # And the markdown's own ':definition' did not become a predicate.
        assert len(subjects[":FileAnalysis"][":definition"]) == 1

    def test_a_prefixed_name_containing_a_dot_survives(self, ttl):
        """':AML.T0000' is why 'a dot ends the statement' is wrong here."""
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        assert ":AML.T0000" in subjects
        assert ":T1204.002" in subjects
        assert subjects[":T1204.002"][":attack-id"] == ["T1204.002"]

    def test_an_escaped_quote_inside_a_literal_is_unescaped(self, ttl):
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        definition = subjects[":T1204.002"][":definition"][0]
        assert '"file"' in definition
        assert "\\" not in definition

    def test_a_blank_node_subject_is_consumed_not_skipped(self, ttl):
        """Skipping leaves the cursor mid-statement and mis-reads the rest."""
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        assert any(name.startswith("_:b") for name in subjects)
        # The statement before it still parsed correctly.
        assert ":version" in subjects

    def test_a_collection_does_not_derail_the_parse(self, ttl):
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        assert subjects[":version"][":definition"]

    def test_restrictions_are_recovered_as_property_target_pairs(self, ttl):
        subjects = d3fend._parse(d3fend._tokenise(ttl.read_text()))
        pairs = d3fend._restrictions(subjects[":FileAnalysis"])
        assert (":analyzes", ":File") in pairs
        assert (":enables", ":Detect") in pairs

    def test_a_prefix_directive_whose_iri_contains_dots_is_skipped_whole(self):
        """The first '.' in '@prefix : <http://d3fend.mitre.org/...' is a trap."""
        tokens = d3fend._tokenise(
            '@prefix : <http://d3fend.mitre.org/ontologies/d3fend.owl#> .\n'
            ':A a owl:Class .\n'
        )
        assert tokens[0] == ("name", ":A")

    def test_the_instrument_check_refuses_a_degraded_parse(self):
        """A hand-written parser that returns something is the silent failure."""
        with pytest.raises(SourceError) as excinfo:
            d3fend._check({":A": {":d3fend-id": ["D3-A"]}})
        assert "Check the parser first" in str(excinfo.value)

    def test_unparseable_syntax_refuses_rather_than_skipping_a_character(self):
        """Skipping a character corrupts every statement after it."""
        with pytest.raises(SourceError) as excinfo:
            d3fend._tokenise(':A a owl:Class ; :p "unterminated .\n')
        assert "unterminated literal" in str(excinfo.value)


class TestD3fend:
    def _docs(self, ttl: Path, monkeypatch) -> dict[str, Document]:
        # The real floors are 450/1400; the fixture is a dozen classes.
        monkeypatch.setattr(d3fend, "_MIN_D3FEND_IDS", 1)
        monkeypatch.setattr(d3fend, "_MIN_ATTACK_IDS", 1)
        return {d.ident: d for d in d3fend._documents(ttl)}

    def test_offensive_classes_are_never_emitted(self, ttl, monkeypatch):
        """They would duplicate the attack and atlas sources outright."""
        docs = self._docs(ttl, monkeypatch)
        assert not [i for i in docs if "T1204.002" in i]
        assert not [i for i in docs if "AML.T0000" in i]

    def test_a_defensive_technique_carries_its_artifacts(self, ttl, monkeypatch):
        technique = self._docs(ttl, monkeypatch)["technique/D3-FA"].text
        assert "analyzes: File" in technique
        assert "Enables (defensive tactic): Detect" in technique
        assert "File Inspection" in technique, "synonyms are the aliasing signal"

    def test_the_artifact_join_is_labelled_as_a_join(self, ttl, monkeypatch):
        """Measured: 1 of 497 d3fend-id classes has a direct edge to attack-id.

        So 'D3-FA counters T1204.002' would be asserting a triple MITRE does
        not ship in this file.
        """
        technique = self._docs(ttl, monkeypatch)["technique/D3-FA"].text
        assert "artifact join, not an asserted countermeasure mapping" in technique
        assert "T1204.002 Malicious File" in technique
        assert "counters" not in technique

    def test_an_artifact_document_shows_both_sides(self, ttl, monkeypatch):
        artifact = self._docs(ttl, monkeypatch)["artifact/File"].text
        assert "D3-FA File Analysis" in artifact
        assert "T1204.002 Malicious File" in artifact

    def test_artifacts_are_system_register_not_adversary(self, ttl, monkeypatch):
        """Calling an artifact definition ADVERSARY would falsify the report."""
        docs = self._docs(ttl, monkeypatch)
        assert docs["artifact/File"].register is Register.SYSTEM
        assert docs["technique/D3-FA"].register is Register.ADVERSARY
        assert docs["technique/D3-FA"].side is Side.BLUE

    def test_the_tactic_lists_the_techniques_that_enable_it(self, ttl, monkeypatch):
        tactic = self._docs(ttl, monkeypatch)["tactic/Detect"].text
        assert "D3-FA File Analysis" in tactic

    def test_reference_authors_and_abstracts_are_never_read(self, ttl, monkeypatch):
        """326 named individuals and 340 third-party abstracts, excluded."""
        docs = self._docs(ttl, monkeypatch)
        joined = "\n".join(d.text for d in docs.values())
        assert "A Named Researcher" not in joined
        assert "quoted into MITRE's graph" not in joined
        assert "A Published Paper About File Analysis" in joined

    def test_the_relation_vocabulary_is_emitted(self, ttl, monkeypatch):
        """Without it the artifact edges are labels the model has to guess."""
        docs = self._docs(ttl, monkeypatch)
        vocabulary = [d for i, d in docs.items() if i.startswith("vocabulary/")]
        assert vocabulary
        assert "x analyzes y" in vocabulary[0].text

    def test_ordering_is_stable_across_runs(self, ttl, monkeypatch):
        first = list(self._docs(ttl, monkeypatch))
        second = list(self._docs(ttl, monkeypatch))
        assert first == second

    def test_analytic_methods_are_not_labelled_defensive_techniques(
            self, ttl, monkeypatch):
        """The bug a uniqueness test surfaced, pinned.

        226 of the 497 d3fend-id classes are :AnalyticTechnique descendants —
        D3FEND's catalogue of machine-learning and statistical methods — and
        selecting techniques by "has a d3fend-id" emitted every one of them
        under "Type: Defensive technique". No document count would have shown
        it; the corpus would simply have contained 226 false statements.
        """
        docs = self._docs(ttl, monkeypatch)
        assert "technique/D3-FA" in docs
        assert "Type: Defensive technique" in docs["technique/D3-FA"].text
        methods = {i: d for i, d in docs.items() if i.startswith("method/")}
        assert methods, "the analytic methods must still be emitted"
        for ident, doc in methods.items():
            assert "Type: Analytic method" in doc.text, ident
            assert "Type: Defensive technique" not in doc.text, ident

    def test_an_analytic_method_is_prose_not_adversary(self, ttl, monkeypatch):
        """An explanation of clustering is not adversary behaviour."""
        docs = self._docs(ttl, monkeypatch)
        method = next(d for i, d in docs.items() if i.startswith("method/"))
        assert method.register is Register.PROSE
        assert method.side is Side.NEUTRAL

    def test_colliding_upstream_ids_do_not_collide_in_idents(
            self, ttl, monkeypatch):
        """Upstream gave the same D3A- id to two classes, 27 times over.

        ``D3A-AL`` is both Active Learning and Alethic Logic. Keying the ident
        on the identifier would silently emit one document twice and make the
        build report ambiguous, so methods are keyed on the class name.
        """
        docs = self._docs(ttl, monkeypatch)
        methods = sorted(i for i in docs if i.startswith("method/"))
        assert "method/ActiveLearning" in methods
        assert "method/AlethicLogic" in methods
        assert len(methods) == len(set(methods))

    def test_a_class_name_with_no_label_still_reads_as_words(self):
        assert d3fend._declassify(":NetworkTraffic") == "Network Traffic"
        assert d3fend._declassify(":File") == "File"

    def test_ancestor_walk_survives_a_cycle(self):
        """A mis-asserted inverse upstream must not be a RecursionError."""
        graph = d3fend._Graph({":A": {"rdfs:subClassOf": [":B"]},
                               ":B": {"rdfs:subClassOf": [":A"]}})
        assert graph.ancestors(":A") == {":A", ":B"}


# ------------------------------------------------------------------- attackflow


def _afb(objects: list[dict], author_email: str = "analyst@example.org") -> dict:
    flow = {
        "id": "flow",
        "instance": "flow-0",
        "properties": [
            ["name", "Test Intrusion"],
            ["description", "A flow written for this test, described at enough "
                            "length that the rendered document clears the "
                            "character floor without any help."],
            ["author", [["name", "An Analyst"],
                        ["contact_information", author_email]]],
            ["scope", "incident"],
            ["external_references", [
                ["hash1", [["source_name", "A Vendor Blog"],
                           ["description", "Blog"],
                           ["url", "https://example.invalid/post"]]],
            ]],
            ["created", "2023-04-21T17:46:00.235Z"],
        ],
        "objects": [o["instance"] for o in objects],
    }
    return {"schema": "attack_flow_v2", "objects": [flow] + objects,
            "layout": {}, "camera": {}}


def _action(instance: str, name: str, technique: str, tactic: str,
            description: str, anchor: str, latch: str) -> dict:
    return {
        "id": "action", "instance": instance,
        "properties": [
            ["name", name], ["tactic_id", tactic],
            ["tactic_ref", "x-mitre-tactic--deadbeef"],
            ["technique_id", technique],
            ["technique_ref", "attack-pattern--deadbeef"],
            ["description", description], ["confidence", None],
            ["ttp", [["tactic", tactic], ["technique", technique]]],
        ],
        "anchors": {"0": anchor},
    }


def _wire(source_latch: str, target_latch: str, instance: str) -> list[dict]:
    return [{"id": "dynamic_line", "instance": instance,
             "source": source_latch, "target": target_latch,
             "handles": []}]


def _anchor(instance: str, latches: list[str]) -> dict:
    return {"id": "vertical_anchor", "instance": instance, "latches": latches}


def _simple_flow() -> dict:
    first = _action("a1", "Malicious File", "T1204.002", "TA0002",
                    "The user opens a disk image file which installs its "
                    "components invisibly.", "anchor-1", "latch-1")
    second = _action("a2", "Install Root Certificate", "T1553.004", "TA0005",
                     "The malware installs a certificate into the system "
                     "trust store.", "anchor-2", "latch-2")
    objects = [first, second,
               _anchor("anchor-1", ["latch-1"]),
               _anchor("anchor-2", ["latch-2"]),
               {"id": "generic_latch", "instance": "latch-1"},
               {"id": "generic_latch", "instance": "latch-2"}]
    objects += _wire("latch-1", "latch-2", "line-1")
    return _afb(objects)


class TestAttackFlowEdges:
    """The graph is stored through the editor's layout model, not as source/target."""

    def test_an_edge_is_recovered_through_latch_anchor_owner(self):
        payload = _simple_flow()
        assert attackflow._edges(payload["objects"]) == [("a1", "a2")]

    def test_a_line_with_an_orphaned_latch_is_dropped_not_fatal(self):
        payload = _simple_flow()
        payload["objects"] += _wire("latch-missing", "latch-2", "line-2")
        assert attackflow._edges(payload["objects"]) == [("a1", "a2")]

    def test_lines_drawn_but_no_edges_resolvable_refuses(self):
        """File order looks like execution order and is not. No fallback."""
        payload = _simple_flow()
        for obj in payload["objects"]:
            if obj.get("id") == "vertical_anchor":
                obj["latches"] = []
        with pytest.raises(SourceError) as excinfo:
            attackflow._flow_document(payload, "test.afb", [])
        assert "do not fall back to file order" in str(excinfo.value)

    def test_the_sequence_is_rendered_in_causal_order(self):
        text = attackflow._flow_document(_simple_flow(), "test.afb", [])
        assert text.index("T1204.002") < text.index("T1553.004")
        assert "-> then: T1553.004 (TA0005) — Install Root Certificate" in text

    def test_a_cycle_is_reported_as_a_cycle_not_forced_into_an_order(self):
        """Flows genuinely loop; inventing a position fabricates a sequence."""
        payload = _simple_flow()
        payload["objects"] += [
            _anchor("anchor-3", ["latch-3"]),
            {"id": "generic_latch", "instance": "latch-3"},
        ]
        # Give a2 a second anchor so it can be a line source, then wire a2->a1.
        for obj in payload["objects"]:
            if obj.get("instance") == "a2":
                obj["anchors"]["30"] = "anchor-3"
        payload["objects"] += _wire("latch-3", "latch-1", "line-2")
        text = attackflow._flow_document(payload, "test.afb", [])
        assert "Actions in a cycle" in text

    def test_ordering_is_stable_across_runs(self):
        payload = _simple_flow()
        first = attackflow._flow_document(payload, "test.afb", [])
        second = attackflow._flow_document(payload, "test.afb", [])
        assert first == second


class TestAttackFlowPrivacy:
    def test_the_flow_authors_name_and_address_never_reach_the_document(self):
        """36 of 41 flows carry an analyst's work email in the author field."""
        text = attackflow._flow_document(_simple_flow(), "test.afb", [])
        assert "analyst@example.org" not in text
        assert "An Analyst" not in text

    def test_the_excluded_object_types_are_excluded_by_whitelist(self):
        """A new observable type upstream must be out until somebody looks."""
        for excluded in ("note", "threat_actor", "user_account", "identity",
                         "email_address", "url", "ipv4_addr", "domain_name",
                         "location", "artifact"):
            assert excluded not in attackflow._RENDERED, excluded

    def test_a_threat_actor_object_naming_an_individual_is_not_rendered(self):
        """Three PLA members named in a US indictment are in the real corpus."""
        payload = _simple_flow()
        payload["objects"].append({
            "id": "threat_actor", "instance": "ta1",
            "properties": [["name", "A Named Individual"],
                           ["description", "Indicted for computer fraud."]],
        })
        text = attackflow._flow_document(payload, "test.afb", [])
        assert "A Named Individual" not in text

    def test_a_home_directory_path_drops_the_object_and_is_counted(self):
        payload = _simple_flow()
        payload["objects"].append({
            "id": "file", "instance": "f1",
            "properties": [["name", "payload.bin"],
                           ["description", "Written to /home/somebody/.cache"]],
        })
        dropped: list[str] = []
        text = attackflow._flow_document(payload, "test.afb", dropped)
        assert "somebody" not in text
        assert len(dropped) == 1
        assert "sha256[:8]=" in dropped[0]
        assert "somebody" not in dropped[0], "the report must not quote it"

    @pytest.mark.parametrize("path", [
        r"C:\Users\Public\Downloads\x.exe",
        "/home/www-data/app",
        "/home/root/.ssh",
        r"C:\Users\Default\AppData",
    ])
    def test_an_impersonal_system_path_is_kept(self, path):
        """Over-dropping deletes corpus content; the filter must be precise."""
        assert attackflow._carries_personal_data(path) == "", path

    @pytest.mark.parametrize("path", [
        r"C:\Users\jsmith\AppData\Roaming",
        "/home/egle/Documents",
    ])
    def test_a_personal_path_is_flagged(self, path):
        assert attackflow._carries_personal_data(path) == "home-directory path"

    def test_file_hashes_are_not_read(self):
        """An indicator list is a lookup table, not knowledge."""
        assert "hashes" in attackflow._NEVER_READ
        payload = _simple_flow()
        payload["objects"].append({
            "id": "file", "instance": "f2",
            "properties": [["name", "dropper.dll"],
                           ["hashes", [["h", [["name", "SHA-256"],
                                              ["value", "a" * 64]]]]],
                           ["mime_type", "application/x-dosexec"]],
        })
        text = attackflow._flow_document(payload, "test.afb", [])
        assert "dropper.dll" in text
        assert "a" * 64 not in text

    def test_stix_refs_are_not_read(self):
        """A STIX UUID beside a technique id teaches the tokenizer a hash."""
        text = attackflow._flow_document(_simple_flow(), "test.afb", [])
        assert "attack-pattern--deadbeef" not in text
        assert "x-mitre-tactic--deadbeef" not in text

    def test_a_process_command_line_is_kept(self):
        """Real command lines from real intrusions are what SHELL is short of."""
        payload = _simple_flow()
        payload["objects"].append({
            "id": "process", "instance": "p1",
            "properties": [["command_line", "net user /domain"],
                           ["pid", None]],
        })
        text = attackflow._flow_document(payload, "test.afb", [])
        assert "net user /domain" in text

    def test_a_filename_from_the_listing_cannot_escape_the_cache(self):
        """The listing is remote data and the name becomes a path."""
        for hostile in ("../../etc/passwd.afb", "/abs/path.afb",
                        "sub/dir.afb", ".hidden.afb"):
            assert ("/" in hostile or "\\" in hostile
                    or hostile.startswith(".")), hostile

    def test_the_url_quoter_encodes_a_space_and_never_a_slash(self):
        """Flow filenames contain spaces, ampersands and parentheses."""
        assert attackflow.quote("Conti Ransomware.afb") == \
            "Conti%20Ransomware.afb"
        assert "/" not in attackflow.quote("a/b.afb")


# ------------------------------------------------------- against the real caches


class TestAgainstTheRealCaches:
    """The only tests that can say "does this still agree with upstream".

    They skip without a cache rather than reaching for the network: a test that
    needs 20 MB of download to pass is a test somebody deletes.
    """

    @pytest.mark.parametrize("module", _FAMILY, ids=lambda m: m.SPEC.name)
    def test_the_adapter_meets_its_own_declared_floor(self, module):
        cache = _cached(module.SPEC.name)
        count = sum(1 for _ in module.SPEC.documents(
            cache / atlas._DATA if module is atlas else cache))
        assert count >= module.SPEC.expect_min_docs, (
            f"{module.SPEC.name} yielded {count} documents against a declared "
            f"floor of {module.SPEC.expect_min_docs}"
        )

    @pytest.mark.parametrize("module", _FAMILY, ids=lambda m: m.SPEC.name)
    def test_no_document_carries_an_address_or_a_handle(self, module):
        cache = _cached(module.SPEC.name)
        for doc in module.SPEC.documents(
                cache / atlas._DATA if module is atlas else cache):
            assert not module._EMAIL.search(doc.text), doc.ident
            assert not module._HANDLE.search(doc.text), doc.ident

    @pytest.mark.parametrize("module", _FAMILY, ids=lambda m: m.SPEC.name)
    def test_idents_are_unique_within_a_source(self, module):
        """A repeated ident makes the build report and --report ambiguous."""
        cache = _cached(module.SPEC.name)
        idents = [d.ident for d in module.SPEC.documents(
            cache / atlas._DATA if module is atlas else cache)]
        duplicates = {i for i in idents if idents.count(i) > 1} \
            if len(idents) != len(set(idents)) else set()
        assert not duplicates, f"{module.SPEC.name}: {sorted(duplicates)[:5]}"

    @pytest.mark.parametrize("module", _FAMILY, ids=lambda m: m.SPEC.name)
    def test_the_licence_file_is_in_the_cache_where_the_spec_says(self, module):
        """A licence claim checkable only by visiting a URL is not checkable."""
        cache = _cached(module.SPEC.name)
        licences = sorted((cache / "licenses").glob("*"))
        assert licences, f"{module.SPEC.name} wrote no licenses/ file"
        for path in licences:
            assert path.stat().st_size > 400, path

    def test_mispgalaxy_does_not_restate_attackactors(self):
        """Measured 8-gram overlap was 0.24%, with no document over 50%.

        The requirement is "do not duplicate an existing source", and the only
        honest way to hold that is to measure it rather than to assert that two
        upstreams are different.
        """
        import re as _re

        misp = _cached("mispgalaxy")
        actors = _cached("attackactors") / "enterprise-attack.json.gz"
        if not actors.is_file():
            pytest.skip("no attackactors cache")
        from training.corpus.sources import attackactors

        def shingles(text: str, width: int = 8) -> set[tuple[str, ...]]:
            words = _re.findall(r"[a-z0-9]+", text.lower())
            return {tuple(words[i:i + width])
                    for i in range(max(0, len(words) - width + 1))}

        existing: set[tuple[str, ...]] = set()
        for doc in attackactors.SPEC.documents(actors):
            existing |= shingles(doc.text)

        worst = 0.0
        for doc in mispgalaxy.SPEC.documents(misp):
            own = shingles(doc.text)
            if own:
                worst = max(worst, len(own & existing) / len(own))
        assert worst < 0.75, f"a mispgalaxy document is {worst:.0%} attackactors"

    def test_d3fend_emits_no_attack_identifier_as_a_document(self):
        """The ontology embeds 1,142 T#### and 189 AML.T#### classes."""
        cache = _cached("d3fend")
        import re as _re

        pattern = _re.compile(r"/(?:T\d{4}|AML\.)")
        for doc in d3fend.SPEC.documents(cache):
            assert not pattern.search(doc.ident), doc.ident

    @pytest.mark.parametrize("module", _FAMILY, ids=lambda m: m.SPEC.name)
    def test_indentation_survives_normalise(self, module):
        """normalise() must not collapse horizontal whitespace. +47% rode on it."""
        cache = _cached(module.SPEC.name)
        for doc in module.SPEC.documents(
                cache / atlas._DATA if module is atlas else cache):
            assert doc.text == normalise(doc.text), doc.ident

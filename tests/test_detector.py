"""Stage 6 checks: the detector.

Each test covers one behaviour. The seeded workspace lives in a temporary
directory, so the committed workspace is never touched.
"""

import base64
import csv
import time

import pytest

from backend import config, detector, seeder
from scripts import generate_workspace as gw


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    """A seeded workspace, with handles on one decoy of each type."""
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    gw.generate(root)
    seeder.seed()

    canaries = seeder.list_registered_canaries()
    by_type: dict[str, list] = {}
    for canary in canaries:
        by_type.setdefault(canary.canary_type, []).append(canary)

    customer = by_type["customer"][0]
    return {
        "root": root,
        "canaries": canaries,
        "customer": customer,
        "customer_email": customer.strong_values()[0],
        "customer_phone": customer.strong_values()[1],
        "customer_id": customer.strong_values()[2],
        "customer_name": customer.weak_values()[0],
        "customer_address": customer.weak_values()[1],
        "customer_postal": customer.weak_values()[2],
        "salary": by_type["salary"][0],
        "credential": by_type["credential"][0],
        "trade_secret": by_type["trade_secret"][0],
    }


def real_customers():
    path = config.WORKSPACE_DIR / "customers" / "customer_contacts.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


# ---------------------------------------------------------------------------
# STRONG: a value unique to a decoy
# ---------------------------------------------------------------------------


def test_decoy_email_is_strong(seeded):
    findings = detector.find_canaries(
        f"Please contact the customer at {seeded['customer_email']} about the order."
    )

    assert findings.confidence == detector.STRONG
    assert findings.canary_ids == [seeded["customer"].id]


def test_decoy_phone_plain_is_strong(seeded):
    assert detector.find_canaries(seeded["customer_phone"]).confidence == detector.STRONG


def test_decoy_phone_with_spaces_is_strong(seeded):
    digits = seeded["customer_phone"].removeprefix("+65")
    spaced = " ".join(digits)

    assert detector.find_canaries(f"Call {spaced} today").confidence == detector.STRONG


def test_decoy_phone_with_dashes_is_strong(seeded):
    digits = seeded["customer_phone"].removeprefix("+65")
    dashed = f"{digits[:4]}-{digits[4:]}"

    assert detector.find_canaries(f"Tel {dashed}").confidence == detector.STRONG


def test_decoy_phone_without_country_code_is_strong(seeded):
    digits = seeded["customer_phone"].removeprefix("+65")

    assert detector.find_canaries(digits).confidence == detector.STRONG


def test_decoy_phone_with_brackets_and_dots_is_strong(seeded):
    digits = seeded["customer_phone"].removeprefix("+65")
    formatted = f"(+65) {digits[:4]}.{digits[4:]}"

    assert detector.find_canaries(formatted).confidence == detector.STRONG


def test_decoy_staff_id_is_strong(seeded):
    staff_id = seeded["salary"].strong_values()[0]

    assert detector.find_canaries(f"Staff {staff_id} payroll").confidence == detector.STRONG


def test_decoy_staff_id_matches_case_insensitively(seeded):
    staff_id = seeded["salary"].strong_values()[0].lower()

    assert detector.find_canaries(staff_id).confidence == detector.STRONG


def test_decoy_api_key_is_strong(seeded):
    api_key = seeded["credential"].strong_values()[0]

    assert detector.find_canaries(f"key: {api_key}").confidence == detector.STRONG


def test_decoy_contract_number_is_strong(seeded):
    contract = seeded["trade_secret"].strong_values()[0]

    assert detector.find_canaries(f"Agreement {contract}").confidence == detector.STRONG


def test_decoy_customer_id_is_strong(seeded):
    assert (
        detector.find_canaries(f"Account {seeded['customer_id']}").confidence
        == detector.STRONG
    )


def test_findings_name_the_file_the_decoy_came_from(seeded):
    findings = detector.find_canaries(seeded["customer_email"])

    assert findings.locations == ["workspace/customers/customer_contacts.csv"]
    assert findings.matches[0].record_ref.startswith("row ")


# ---------------------------------------------------------------------------
# Encoded content
# ---------------------------------------------------------------------------


def test_base64_decoy_email_is_strong(seeded):
    encoded = base64.b64encode(seeded["customer_email"].encode()).decode()

    findings = detector.find_canaries(f"For secure transfer: {encoded}")

    assert findings.confidence == detector.STRONG


def test_hex_decoy_phone_is_strong(seeded):
    digits = seeded["customer_phone"].removeprefix("+65")
    encoded = digits.encode().hex()

    assert detector.find_canaries(f"ref {encoded}").confidence == detector.STRONG


def test_url_encoded_decoy_email_is_strong(seeded):
    encoded = seeded["customer_email"].replace("@", "%40").replace(".", "%2E")

    findings = detector.find_canaries(f"http://track.test/?c={encoded}")

    assert findings.confidence == detector.STRONG


def test_url_encoded_decoy_phone_in_a_link_is_strong(seeded):
    findings = detector.find_canaries(
        f"http://track.test/?p=%2B65{seeded['customer_phone'].removeprefix('+65')}"
    )

    assert findings.confidence == detector.STRONG


def test_base64_of_a_whole_decoy_row_is_strong(seeded):
    row = f"{seeded['customer_id']},{seeded['customer_name']},{seeded['customer_email']}"
    encoded = base64.b64encode(row.encode()).decode()

    assert detector.find_canaries(encoded).confidence == detector.STRONG


def test_decoding_is_one_level_only(seeded):
    """Double-encoded content is not pursued; the caps are the point."""
    once = base64.b64encode(seeded["customer_email"].encode()).decode()
    twice = base64.b64encode(once.encode()).decode()

    assert detector.find_canaries(twice).confidence == detector.NONE


def test_decode_candidates_respects_the_candidate_cap():
    blocks = " ".join(
        base64.b64encode(f"candidate number {index:04d}".encode()).decode()
        for index in range(200)
    )

    assert len(detector.decode_candidates(blocks)) <= detector.MAX_CANDIDATES


def test_decode_candidates_ignores_blocks_that_are_too_short():
    short = base64.b64encode(b"hi").decode()

    assert detector.decode_candidates(short) == []


def test_decode_candidates_ignores_binary_results():
    """A block that decodes to bytes, not text, is not a candidate."""
    noise = base64.b64encode(bytes(range(0, 32)) * 4).decode()

    assert all("\x00" not in candidate for candidate in detector.decode_candidates(noise))


def test_decode_candidates_finds_hex_and_base64_together():
    candidates = detector.decode_candidates(
        f"{base64.b64encode(b'first value here').decode()} "
        f"{b'second value here'.hex()}"
    )

    joined = " ".join(candidates)
    assert "first value here" in joined
    assert "second value here" in joined


# ---------------------------------------------------------------------------
# WEAK and NONE
# ---------------------------------------------------------------------------


def test_decoy_name_alone_is_none(seeded):
    """A name alone is never even WEAK."""
    findings = detector.find_canaries(
        f"I spoke to {seeded['customer_name']} about the delivery."
    )

    assert findings.confidence == detector.NONE
    assert findings.matches == []


def test_decoy_name_plus_address_is_weak(seeded):
    findings = detector.find_canaries(
        f"{seeded['customer_name']} lives at {seeded['customer_address']}."
    )

    assert findings.confidence == detector.WEAK
    assert findings.matches[0].canary_id == seeded["customer"].id


def test_weak_match_reports_which_values_matched(seeded):
    findings = detector.find_canaries(
        f"{seeded['customer_name']}, {seeded['customer_address']}"
    )

    assert len(findings.matches[0].matched_values) >= 2


def test_decoy_name_fuzzy_variant_plus_address_is_weak(seeded):
    """token_sort_ratio >= 90, so a reordered name still matches."""
    parts = seeded["customer_name"].split()
    reordered = " ".join(reversed(parts))

    findings = detector.find_canaries(f"{reordered} at {seeded['customer_address']}")

    assert findings.confidence == detector.WEAK


def test_decoy_salary_name_plus_amount_is_weak(seeded):
    name, amount = seeded["salary"].weak_values()

    findings = detector.find_canaries(f"{name} earns {amount} per month")

    assert findings.confidence == detector.WEAK


def test_a_strong_value_outranks_weak_values(seeded):
    findings = detector.find_canaries(
        f"{seeded['customer_name']}, {seeded['customer_address']}, "
        f"{seeded['customer_email']}"
    )

    assert findings.confidence == detector.STRONG
    assert findings.matches[0].confidence == detector.STRONG


def test_ordinary_text_is_none(seeded):
    findings = detector.find_canaries(
        "Thank you for your enquiry. Our refund policy allows returns within "
        "14 days of delivery, and delivery is free above 300 dollars."
    )

    assert findings.confidence == detector.NONE


def test_empty_text_is_none(seeded):
    assert detector.find_canaries("").confidence == detector.NONE


def test_real_customer_data_is_none(seeded):
    """A real customer's details are not a decoy, however sensitive."""
    decoy_emails = {
        canary.strong_values()[0]
        for canary in seeded["canaries"]
        if canary.canary_type == "customer"
    }
    real = next(row for row in real_customers() if row["email"] not in decoy_emails)

    findings = detector.find_canaries(
        f"{real['name']}, {real['email']}, {real['phone']}, {real['address']}"
    )

    assert findings.confidence == detector.NONE


def test_the_whole_refund_policy_is_none(seeded):
    text = (config.WORKSPACE_DIR / "product_docs" / "refund_policy.txt").read_text()

    assert detector.find_canaries(text).confidence == detector.NONE


def test_after_unseed_previously_planted_values_are_none(seeded):
    email = seeded["customer_email"]
    assert detector.find_canaries(email).confidence == detector.STRONG

    seeder.unseed()

    assert detector.find_canaries(email).confidence == detector.NONE


def test_a_removed_canary_stops_matching(seeded):
    email = seeded["customer_email"]
    seeder.set_canary_status(seeded["customer"].id, "removed")

    assert detector.find_canaries(email).confidence == detector.NONE


def test_an_unseeded_workspace_finds_nothing(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    gw.generate(root)
    seeder.init_registry()

    assert detector.find_canaries("anything at all").confidence == detector.NONE


# ---------------------------------------------------------------------------
# Oversized input
# ---------------------------------------------------------------------------


def test_oversized_input_is_handled_without_hanging(seeded):
    """A 5 MB input is capped, not chewed through."""
    payload = ("Lorem ipsum dolor sit amet. " * 200_000)[: 5 * 1024 * 1024]

    started = time.monotonic()
    findings = detector.find_canaries(payload)
    elapsed = time.monotonic() - started

    assert findings.confidence == detector.NONE
    assert elapsed < 10


def test_a_decoy_beyond_the_input_cap_is_not_scanned(seeded):
    """The cap is real: content past 200 KB is not read.

    The timing assertion matters as much as the result. A long run of
    characters that never completes an email or a phone number is exactly the
    input that makes an unbounded quantifier quadratic; both patterns are
    bounded so this stays fast.
    """
    padding = "x" * (detector.MAX_INPUT_BYTES + 1000)

    started = time.monotonic()
    findings = detector.find_canaries(padding + seeded["customer_email"])
    elapsed = time.monotonic() - started

    assert findings.confidence == detector.NONE
    assert elapsed < 5


def test_pathological_inputs_stay_fast(seeded):
    """One guard per shape that has previously been slow."""
    shapes = {
        "spaces": " " * detector.MAX_INPUT_BYTES,
        "letters": "x" * detector.MAX_INPUT_BYTES,
        "digits": "9" * detector.MAX_INPUT_BYTES,
        "at_signs": "@" * detector.MAX_INPUT_BYTES,
        "mixed": ("aB9.+-@" * 30_000),
    }

    for label, payload in shapes.items():
        started = time.monotonic()
        detector.find_canaries(payload)
        detector.extract_personal(payload)
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"{label} took {elapsed:.1f}s"


def test_a_decoy_inside_the_input_cap_is_still_found(seeded):
    padding = "padding text. " * 100

    findings = detector.find_canaries(padding + seeded["customer_email"])

    assert findings.confidence == detector.STRONG


def test_many_digit_runs_do_not_hang(seeded):
    payload = " ".join(str(index) for index in range(100_000))

    started = time.monotonic()
    detector.find_canaries(payload)

    assert time.monotonic() - started < 10


# ---------------------------------------------------------------------------
# extract_personal
# ---------------------------------------------------------------------------


def test_extract_personal_finds_an_sg_phone(seeded):
    items = detector.extract_personal("Call me on +65 9123 4567 tomorrow")

    assert detector.PersonalItem("phone", "91234567") in items


def test_extract_personal_finds_an_email(seeded):
    items = detector.extract_personal("Write to Someone@Example.COM please")

    assert detector.PersonalItem("email", "someone@example.com") in items


def test_extract_personal_finds_a_staff_id(seeded):
    items = detector.extract_personal("Approved by LC-0142")

    assert detector.PersonalItem("staff_id", "LC-0142") in items


def test_extract_personal_finds_a_postal_code(seeded):
    items = detector.extract_personal("Deliver to Singapore 521123")

    assert detector.PersonalItem("postal_code", "521123") in items


def test_extract_personal_detects_an_artificial_nric_shaped_string(seeded):
    """The dataset has no NRICs; this pattern is tested on a made-up string."""
    items = detector.extract_personal("Identity reference S1234567D on file")

    assert detector.PersonalItem("nric", "S1234567D") in items


def test_a_phones_digits_are_not_also_counted_as_a_postal_code(seeded):
    items = detector.extract_personal("+6591234567")

    kinds = {item.kind for item in items}
    assert kinds == {"phone"}


def test_extract_personal_deduplicates(seeded):
    items = detector.extract_personal(
        "me@example.com and again me@example.com and +6591234567, +65 9123 4567"
    )

    assert len(items) == 2


def test_extract_personal_on_ordinary_text_finds_nothing(seeded):
    assert detector.extract_personal("Our opening hours are 9am to 6pm.") == []


def test_count_personal_counts_distinct_items(seeded):
    text = "a@example.com, b@example.net, +6591234567, LC-0142, Singapore 521123"

    assert detector.count_personal(text) == 5


def test_extract_personal_is_capped_on_huge_input(seeded):
    payload = "a@example.com " * 100_000

    started = time.monotonic()
    detector.extract_personal(payload)

    assert time.monotonic() - started < 10


# ---------------------------------------------------------------------------
# owner_lookup
# ---------------------------------------------------------------------------


def test_owner_lookup_finds_the_right_owner_by_email(seeded):
    real = real_customers()[0]

    result = detector.owner_lookup([detector.PersonalItem("email", real["email"])])

    owner = result[real["email"].lower()]
    assert owner.record_type == "customer"
    assert owner.name == real["name"]


def test_owner_lookup_finds_the_right_owner_by_phone(seeded):
    real = real_customers()[0]
    canonical = detector.canonicalise_phone(real["phone"])

    result = detector.owner_lookup([detector.PersonalItem("phone", canonical)])

    assert result[canonical].record_id == real["customer_id"]


def test_owner_lookup_finds_a_customer_by_id(seeded):
    real = real_customers()[0]

    result = detector.owner_lookup([real["customer_id"]])

    assert result[real["customer_id"].lower()].name == real["name"]


def test_owner_lookup_finds_staff_by_staff_id(seeded):
    path = config.WORKSPACE_DIR / "hr" / "employees.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        staff = next(csv.DictReader(handle))

    result = detector.owner_lookup([detector.PersonalItem("staff_id", staff["staff_id"])])

    owner = result[staff["staff_id"].lower()]
    assert owner.record_type == "staff"
    assert owner.name == staff["name"]


def test_owner_lookup_returns_none_for_an_unknown_identifier(seeded):
    result = detector.owner_lookup([detector.PersonalItem("email", "nobody@example.com")])

    assert result["nobody@example.com"] is None


def test_a_postal_code_never_decides_ownership(seeded):
    real = real_customers()[0]

    result = detector.owner_lookup(
        [detector.PersonalItem("postal_code", real["postal_code"])]
    )

    assert result[real["postal_code"]] is None


def test_a_name_never_decides_ownership(seeded):
    real = real_customers()[0]

    result = detector.owner_lookup([real["name"]])

    assert result[real["name"]] is None


def test_a_duplicated_phone_is_ambiguous(tmp_path, monkeypatch):
    """Two records sharing a phone cannot establish an owner."""
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    gw.generate(root)

    path = root / "customers" / "customer_contacts.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(rows[0])

    shared_phone = rows[0]["phone"]
    duplicate = dict(rows[1])
    duplicate["phone"] = shared_phone
    rows.append(duplicate)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    canonical = detector.canonicalise_phone(shared_phone)
    result = detector.owner_lookup([detector.PersonalItem("phone", canonical)])

    assert result[canonical] == detector.AMBIGUOUS


def test_owner_lookup_handles_several_items_at_once(seeded):
    rows = real_customers()
    items = [
        detector.PersonalItem("email", rows[0]["email"]),
        detector.PersonalItem("phone", detector.canonicalise_phone(rows[1]["phone"])),
        detector.PersonalItem("postal_code", rows[2]["postal_code"]),
    ]

    result = detector.owner_lookup(items)

    assert len(result) == 3
    assert sum(1 for value in result.values() if isinstance(value, detector.Owner)) == 2


# ---------------------------------------------------------------------------
# Canonicalisation is type-specific, not global
# ---------------------------------------------------------------------------


def test_phone_canonicalisation_strips_only_inside_the_token():
    assert detector.canonicalise_phone("+65 9823 1764") == "98231764"
    assert detector.canonicalise_phone("(+65) 9823-1764") == "98231764"
    assert detector.canonicalise_phone("9 8 2 3 1 7 6 4") == "98231764"
    assert detector.canonicalise_phone("98231764") == "98231764"


def test_phone_canonicalisation_rejects_things_that_are_not_phones():
    assert detector.canonicalise_phone("12345678") is None
    assert detector.canonicalise_phone("521123") is None
    assert detector.canonicalise_phone("1234567890123456") is None
    assert detector.canonicalise_phone("") is None


def test_email_canonicalisation():
    assert detector.canonicalise_email("  Mei.Ling.TAN@Example.COM ") == (
        "mei.ling.tan@example.com"
    )


def test_name_canonicalisation_collapses_whitespace():
    assert detector.canonicalise_name("  Mei   Ling\tTan ") == "mei ling tan"


def test_value_classification_picks_the_right_matcher():
    assert detector.classify_value("a@example.com") == detector.KIND_EMAIL
    assert detector.classify_value("+6598231764") == detector.KIND_PHONE
    assert detector.classify_value("521123") == detector.KIND_POSTAL
    assert detector.classify_value("4700") == detector.KIND_AMOUNT
    assert detector.classify_value("LC-0142") == detector.KIND_IDENTIFIER
    assert detector.classify_value("pk_live_Rt9mQxBv7TkdLwEz") == detector.KIND_IDENTIFIER
    assert detector.classify_value("SPA-2026-7670") == detector.KIND_IDENTIFIER
    assert detector.classify_value("Mei Ling Tan") == detector.KIND_NAME
    assert detector.classify_value("Blk 7 Tampines Street 11, Singapore 521123") == (
        detector.KIND_TEXT
    )


def test_an_identifier_does_not_match_a_longer_string(seeded):
    """LC-0142 must not match inside LC-01425."""
    staff_id = seeded["salary"].strong_values()[0]

    assert detector.find_canaries(f"{staff_id}9").confidence == detector.NONE


def test_detector_reads_the_registry_and_the_seeder_writes_it(seeded):
    """Both halves of the registry boundary still work."""
    assert len(detector.load_active_canaries()) == 20
    assert detector.load_canary(seeded["customer"].id) is not None

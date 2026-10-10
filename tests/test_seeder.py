"""Stage 5 checks: the decoy seeder.

Every test runs against a workspace in a temporary directory, so the committed
workspace is never seeded by the suite. The registry is already redirected to
a temporary file by the autouse fixture in conftest.py.
"""

import csv
import hashlib
import json
import re

import pytest

from backend import config, detector, seeder, workspace
from scripts import generate_workspace as gw

NRIC_PATTERN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]\d{7}[A-Za-z](?![A-Za-z0-9])")
CUSTOMER_DOMAINS = ("example.com", "example.net", "example.org")


@pytest.fixture()
def clean_workspace(tmp_path, monkeypatch):
    """A freshly generated, unseeded workspace in a temporary directory."""
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    gw.generate(root)
    return root


def read_csv(relative):
    with (config.WORKSPACE_DIR / relative).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_json(relative):
    return json.loads((config.WORKSPACE_DIR / relative).read_text(encoding="utf-8"))


def read_text(relative):
    return (config.WORKSPACE_DIR / relative).read_text(encoding="utf-8")


def hash_tree(root):
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != ".gitkeep"
    }


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------


def test_seeding_creates_exactly_20_active_canaries(clean_workspace):
    seeder.seed()

    assert len(seeder.list_registered_canaries(status="active")) == 20


def test_the_20_canaries_break_down_as_specified(clean_workspace):
    seeder.seed()

    types = [canary.canary_type for canary in seeder.list_registered_canaries()]

    assert types.count("customer") == 15
    assert types.count("salary") == 3
    assert types.count("credential") == 1
    assert types.count("trade_secret") == 1


def test_215_customer_rows_after_seeding(clean_workspace):
    assert len(read_csv(seeder.CUSTOMERS_CSV)) == 200

    seeder.seed()

    assert len(read_csv(seeder.CUSTOMERS_CSV)) == 215


def test_200_customer_rows_after_unseeding(clean_workspace):
    seeder.seed()
    seeder.unseed()

    assert len(read_csv(seeder.CUSTOMERS_CSV)) == 200


def test_28_staff_rows_after_seeding(clean_workspace):
    seeder.seed()

    assert len(read_csv(seeder.EMPLOYEES_CSV)) == 28
    assert len(read_csv(seeder.SALARIES_CSV)) == 28


def test_decoy_customers_have_one_to_three_orders_each(clean_workspace):
    before = len(read_json(seeder.ORDERS_JSON))
    seeder.seed()
    orders = read_json(seeder.ORDERS_JSON)

    decoy_ids = {
        value
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "customer"
        for value in canary.strong_values()
        if value.startswith("C")
    }
    assert len(decoy_ids) == 15

    for customer_id in decoy_ids:
        count = sum(1 for order in orders if order["customer_id"] == customer_id)
        assert 1 <= count <= 3, customer_id

    assert len(orders) > before


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_seeding_twice_creates_no_duplicates(clean_workspace):
    seeder.seed()
    first = hash_tree(config.WORKSPACE_DIR)

    seeder.seed()

    assert len(seeder.list_registered_canaries(status="active")) == 20
    assert len(read_csv(seeder.CUSTOMERS_CSV)) == 215
    assert hash_tree(config.WORKSPACE_DIR) == first


def test_the_second_seed_reports_that_it_planted_nothing(clean_workspace):
    seeder.seed()
    result = seeder.seed()

    assert result["planted"] == 0
    assert result["canary_count"] == 20


def test_is_seeded_tracks_state(clean_workspace):
    assert seeder.is_seeded() is False

    seeder.seed()
    assert seeder.is_seeded() is True

    seeder.unseed()
    assert seeder.is_seeded() is False


# ---------------------------------------------------------------------------
# Unseed restores the originals exactly
# ---------------------------------------------------------------------------


def test_unseed_restores_every_file_byte_for_byte(clean_workspace):
    """Hashes before seeding must equal hashes after unseeding."""
    before = hash_tree(config.WORKSPACE_DIR)

    seeder.seed()
    assert hash_tree(config.WORKSPACE_DIR) != before

    seeder.unseed()

    assert hash_tree(config.WORKSPACE_DIR) == before


def test_unseed_empties_the_registry(clean_workspace):
    seeder.seed()
    seeder.unseed()

    assert seeder.list_registered_canaries() == []
    assert detector.load_active_canaries() == []


def test_unseed_deletes_the_planted_document(clean_workspace):
    seeder.seed()
    assert (config.WORKSPACE_DIR / seeder.SUPPLIER_TERMS_TXT).exists()

    seeder.unseed()

    assert not (config.WORKSPACE_DIR / seeder.SUPPLIER_TERMS_TXT).exists()


def test_seed_unseed_seed_is_stable(clean_workspace):
    seeder.seed()
    first = hash_tree(config.WORKSPACE_DIR)
    seeder.unseed()
    seeder.seed()

    assert hash_tree(config.WORKSPACE_DIR) == first


# ---------------------------------------------------------------------------
# Strong values are unique
# ---------------------------------------------------------------------------


def test_strong_values_are_unique_across_canaries(clean_workspace):
    seeder.seed()

    all_strong = [
        value
        for canary in seeder.list_registered_canaries()
        for value in canary.strong_values()
    ]

    assert len(set(all_strong)) == len(all_strong)


def test_decoy_emails_and_phones_do_not_collide_with_real_ones(clean_workspace):
    original = read_csv(seeder.CUSTOMERS_CSV)
    real_emails = {row["email"] for row in original}
    real_phones = {row["phone"] for row in original}
    real_ids = {row["customer_id"] for row in original}

    seeder.seed()

    for canary in seeder.list_registered_canaries():
        if canary.canary_type != "customer":
            continue
        email, phone, customer_id = canary.strong_values()
        assert email not in real_emails
        assert phone not in real_phones
        assert customer_id not in real_ids


def test_every_row_in_the_seeded_file_is_still_unique(clean_workspace):
    seeder.seed()
    rows = read_csv(seeder.CUSTOMERS_CSV)

    for column in ("customer_id", "email", "phone"):
        values = [row[column] for row in rows]
        assert len(set(values)) == len(values), column


def test_decoy_staff_ids_are_unique(clean_workspace):
    seeder.seed()
    rows = read_csv(seeder.EMPLOYEES_CSV)

    ids = [row["staff_id"] for row in rows]
    assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# Planted values land in the intended files
# ---------------------------------------------------------------------------


def test_every_canary_value_is_present_in_the_files_it_references(clean_workspace):
    """A "which file leaked" alert names the files from the registry, so every
    strong value has to actually be in one of them.

    A salary decoy spans two files: the salary row and the matching employee
    row. Its location names the sensitive one and its record_ref names the
    other, so both are checked.
    """
    seeder.seed()

    for canary in seeder.list_registered_canaries():
        referenced = re.findall(
            r"workspace/[\w/]+\.\w+", f"{canary.location} {canary.record_ref}"
        )
        assert referenced, canary.location

        combined = "\n".join(
            read_text(path.removeprefix("workspace/")) for path in set(referenced)
        )
        for value in canary.strong_values():
            assert value in combined, f"{value} missing from {referenced}"


def test_customer_decoys_are_in_the_contacts_file(clean_workspace):
    seeder.seed()

    locations = {
        canary.location
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "customer"
    }

    assert locations == {"workspace/customers/customer_contacts.csv"}


def test_salary_decoys_are_in_both_hr_files(clean_workspace):
    seeder.seed()
    employees = read_text(seeder.EMPLOYEES_CSV)
    salaries = read_text(seeder.SALARIES_CSV)

    for canary in seeder.list_registered_canaries():
        if canary.canary_type != "salary":
            continue
        staff_id, email = canary.strong_values()
        assert staff_id in employees
        assert staff_id in salaries
        assert email in employees


def test_credential_decoy_is_an_extra_key_line_in_the_it_file(clean_workspace):
    before = re.findall(
        r"^\s*payment_gateway\.\w+\s*=\s*(\S+)$",
        read_text(seeder.INTEGRATIONS_TXT),
        re.MULTILINE,
    )
    assert len(before) == 2

    seeder.seed()

    after = re.findall(
        r"^\s*payment_gateway\.\w+\s*=\s*(\S+)$",
        read_text(seeder.INTEGRATIONS_TXT),
        re.MULTILINE,
    )
    assert len(after) == 3
    assert all(key.startswith("pk_live_") for key in after)
    assert len(set(after)) == 3


def test_credential_decoy_matches_the_existing_line_format(clean_workspace):
    """The new line is indistinguishable in shape from the two real ones."""
    seeder.seed()
    lines = [
        line
        for line in read_text(seeder.INTEGRATIONS_TXT).split("\n")
        if "payment_gateway." in line and "=" in line
    ]

    assert len(lines) == 3
    # Same indentation, and the '=' falls in the same column on every line.
    indents = {len(line) - len(line.lstrip()) for line in lines}
    equals_columns = {line.index("=") for line in lines}
    assert len(indents) == 1
    assert len(equals_columns) == 1
    # Key bodies are the same length.
    assert len({len(line.split("=")[1].strip()) for line in lines}) == 1


def test_trade_secret_decoy_is_a_plausible_supplier_agreement(clean_workspace):
    seeder.seed()
    text = read_text(seeder.SUPPLIER_TERMS_TXT)

    assert "SUPPLIER PRICE AGREEMENT" in text
    assert "Confidentiality" in text

    canary = next(
        item
        for item in seeder.list_registered_canaries()
        if item.canary_type == "trade_secret"
    )
    contract_number, supplier = canary.strong_values()
    assert re.fullmatch(r"SPA-2026-\d{4}", contract_number)
    assert contract_number in text
    assert supplier in text


def test_the_supplier_name_appears_nowhere_else_in_the_workspace(clean_workspace):
    seeder.seed()
    canary = next(
        item
        for item in seeder.list_registered_canaries()
        if item.canary_type == "trade_secret"
    )
    _, supplier = canary.strong_values()

    hits = [
        path.name
        for path in config.WORKSPACE_DIR.rglob("*")
        if path.is_file()
        and path.name != ".gitkeep"
        and supplier in path.read_text(encoding="utf-8", errors="replace")
    ]

    assert hits == ["supplier_terms_2026.txt"]


def test_record_refs_point_at_the_right_rows(clean_workspace):
    """A "which file leaked" alert needs the row to be correct."""
    seeder.seed()
    rows = read_csv(seeder.CUSTOMERS_CSV)

    for canary in seeder.list_registered_canaries():
        if canary.canary_type != "customer":
            continue
        row_number = int(canary.record_ref.removeprefix("row "))
        email = canary.strong_values()[0]
        assert rows[row_number - 1]["email"] == email


# ---------------------------------------------------------------------------
# Decoys are indistinguishable from real records
# ---------------------------------------------------------------------------


def test_no_decoy_marker_anywhere_in_the_seeded_workspace(clean_workspace):
    seeder.seed()

    markers = re.compile(
        r"\b(decoy|canary|canaries|honeypot|honeytoken|dummy|fake|placeholder|"
        r"synthetic|seeded|test\s+record|test\s+row|sample\s+record|"
        r"do\s+not\s+use)\b",
        re.IGNORECASE,
    )
    offenders = []
    for path in sorted(config.WORKSPACE_DIR.rglob("*")):
        if path.is_file() and path.name != ".gitkeep":
            if markers.search(path.read_text(encoding="utf-8", errors="replace")):
                offenders.append(path.name)

    assert offenders == []


def test_decoy_rows_pass_the_same_validators_as_real_rows(clean_workspace):
    """The Stage 4 validators, applied to the 15 decoy rows specifically."""
    seeder.seed()
    rows = read_csv(seeder.CUSTOMERS_CSV)

    decoy_emails = {
        canary.strong_values()[0]
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "customer"
    }
    decoy_rows = [row for row in rows if row["email"] in decoy_emails]
    assert len(decoy_rows) == 15

    for row in decoy_rows:
        assert re.fullmatch(r"C\d{5}", row["customer_id"]), row
        assert row["email"].split("@")[1] in CUSTOMER_DOMAINS, row
        assert re.fullmatch(r"\+65[89]\d{7}", row["phone"]), row
        assert re.fullmatch(r"\d{6}", row["postal_code"]), row
        assert row["postal_code"] in row["address"], row
        assert "Singapore" in row["address"], row
        assert len(row["name"].split()) >= 2, row


def test_decoy_rows_are_scattered_not_appended(clean_workspace):
    """Position must not give a decoy away."""
    seeder.seed()
    rows = read_csv(seeder.CUSTOMERS_CSV)
    decoy_emails = {
        canary.strong_values()[0]
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "customer"
    }
    positions = [
        index for index, row in enumerate(rows) if row["email"] in decoy_emails
    ]

    assert positions != list(range(200, 215))
    assert min(positions) < 100
    assert max(positions) > 100


def test_decoy_staff_sit_with_real_staff_in_the_same_position(clean_workspace):
    """The payroll file stays grouped by department."""
    seeder.seed()
    rows = read_csv(seeder.EMPLOYEES_CSV)
    decoy_ids = {
        canary.strong_values()[0]
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "salary"
    }

    for index, row in enumerate(rows):
        if row["staff_id"] not in decoy_ids:
            continue
        neighbours = [
            rows[neighbour]["position"]
            for neighbour in (index - 1, index + 1)
            if 0 <= neighbour < len(rows)
        ]
        assert row["position"] in neighbours, row


def test_decoy_salaries_are_in_the_same_band_as_the_position(clean_workspace):
    seeder.seed()
    employees = {row["staff_id"]: row for row in read_csv(seeder.EMPLOYEES_CSV)}
    salaries = read_csv(seeder.SALARIES_CSV)
    decoy_ids = {
        canary.strong_values()[0]
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "salary"
    }

    by_position: dict[str, list[int]] = {}
    for row in salaries:
        position = employees[row["staff_id"]]["position"]
        by_position.setdefault(position, []).append(int(row["monthly_salary"]))

    for row in salaries:
        if row["staff_id"] not in decoy_ids:
            continue
        position = employees[row["staff_id"]]["position"]
        peers = by_position[position]
        assert 2500 <= int(row["monthly_salary"]) <= 12000
        assert min(peers) <= int(row["monthly_salary"]) <= max(peers)


def test_decoy_staff_ids_follow_the_real_format(clean_workspace):
    seeder.seed()

    for canary in seeder.list_registered_canaries():
        if canary.canary_type == "salary":
            assert re.fullmatch(r"LC-\d{4}", canary.strong_values()[0])


def test_decoy_orders_are_not_all_at_the_highest_numbers(clean_workspace):
    seeder.seed()
    orders = read_json(seeder.ORDERS_JSON)
    decoy_ids = {
        value
        for canary in seeder.list_registered_canaries()
        if canary.canary_type == "customer"
        for value in canary.strong_values()
        if value.startswith("C")
    }
    decoy_numbers = [
        order["order_number"] for order in orders if order["customer_id"] in decoy_ids
    ]
    real_numbers = [
        order["order_number"]
        for order in orders
        if order["customer_id"] not in decoy_ids
    ]

    assert min(decoy_numbers) < max(real_numbers)
    assert min(decoy_numbers) < 1300


def test_no_nric_shaped_string_after_seeding(clean_workspace):
    seeder.seed()

    offenders = []
    for path in sorted(config.WORKSPACE_DIR.rglob("*")):
        if path.is_file() and path.name != ".gitkeep":
            text = path.read_text(encoding="utf-8", errors="replace")
            offenders += [f"{path.name}: {m.group(0)}" for m in NRIC_PATTERN.finditer(text)]

    assert offenders == []


def test_seeded_customer_file_still_parses_as_clean_csv(clean_workspace):
    seeder.seed()
    rows = read_csv(seeder.CUSTOMERS_CSV)

    assert len(rows) == 215
    for row in rows:
        assert set(row) == {
            "customer_id",
            "name",
            "email",
            "phone",
            "postal_code",
            "address",
        }
        assert all(value for value in row.values())


# ---------------------------------------------------------------------------
# The registry stays out of reach
# ---------------------------------------------------------------------------


def test_the_registry_is_unreachable_through_workspace_path_utilities(clean_workspace):
    seeder.seed()

    for attempt in (
        "../vault/registry.db",
        "../../vault/registry.db",
        "vault/registry.db",
        "/tmp/registry.db",
    ):
        with pytest.raises(workspace.WorkspaceError):
            workspace.read_file(attempt)


def test_no_workspace_file_contains_a_registry_path(clean_workspace):
    seeder.seed()

    for path in sorted(config.WORKSPACE_DIR.rglob("*")):
        if path.is_file() and path.name != ".gitkeep":
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "registry.db" not in text
            assert "vault/" not in text


def test_listing_the_workspace_never_shows_the_registry(clean_workspace):
    seeder.seed()

    for folder in workspace.list_folders():
        assert "registry.db" not in workspace.list_folder(folder)


# ---------------------------------------------------------------------------
# Admin views
# ---------------------------------------------------------------------------


def test_decoy_map_lists_all_20_with_locations(clean_workspace):
    seeder.seed()
    decoys = seeder.decoy_map()

    assert len(decoys) == 20
    for entry in decoys:
        assert entry["location"].startswith("workspace/")
        assert entry["record_ref"]
        assert entry["strong_values"]
        assert entry["status"] == "active"


def test_summary_reports_counts_per_location(clean_workspace):
    seeder.seed()
    result = seeder.summary()

    assert result["seeded"] is True
    assert result["canary_count"] == 20
    assert result["canaries_per_location"][
        "workspace/customers/customer_contacts.csv"
    ] == 15
    assert result["record_counts"]["workspace/customers/customer_contacts.csv"] == 215


def test_summary_on_an_unseeded_workspace(clean_workspace):
    result = seeder.summary()

    assert result["seeded"] is False
    assert result["canary_count"] == 0
    assert result["record_counts"]["workspace/customers/customer_contacts.csv"] == 200

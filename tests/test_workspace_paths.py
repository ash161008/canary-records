"""Checks: workspace path safety.

Each test covers one way a path could escape the workspace.
"""

import pytest

from backend import config, workspace


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    """A small workspace in a temporary directory, with a secret outside it."""
    root = tmp_path / "workspace"
    (root / "customers").mkdir(parents=True)
    (root / "hr").mkdir()
    (root / "customers" / "orders.json").write_text("[]", encoding="utf-8")
    (root / "hr" / "salaries.csv").write_text("staff_id\n", encoding="utf-8")

    (tmp_path / "secret.txt").write_text("outside the workspace", encoding="utf-8")
    (tmp_path / "vault").mkdir()
    (tmp_path / "vault" / "registry.db").write_text("decoy map", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "app.db").write_text("app data", encoding="utf-8")

    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    return tmp_path


# ---------------------------------------------------------------------------
# Valid paths
# ---------------------------------------------------------------------------


def test_a_valid_relative_path_resolves(sandbox):
    assert workspace.resolve_path("customers/orders.json").is_file()


def test_a_workspace_prefixed_path_resolves_to_the_same_file(sandbox):
    assert workspace.resolve_path("workspace/customers/orders.json") == (
        workspace.resolve_path("customers/orders.json")
    )


def test_a_valid_file_is_readable(sandbox):
    assert workspace.read_file("customers/orders.json") == "[]"


def test_listing_a_folder_returns_its_files(sandbox):
    assert workspace.list_folder("customers") == ["orders.json"]


def test_the_real_workspace_files_are_readable():
    """The committed workspace, not a sandbox."""
    text = workspace.read_file("customers/customer_contacts.csv")

    assert text.startswith("customer_id,name,email,phone,postal_code,address")


def test_real_folder_counts_cover_every_folder():
    counts = workspace.folder_counts()

    assert set(counts) == {"inbox", "customers", "hr", "product_docs", "it"}
    assert counts["customers"] == 2
    assert counts["product_docs"] == 4


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------


def test_parent_traversal_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="traversal"):
        workspace.resolve_path("../../secret.txt")


def test_single_level_traversal_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="traversal"):
        workspace.resolve_path("../secret.txt")


def test_traversal_hidden_mid_path_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="traversal"):
        workspace.resolve_path("customers/../../secret.txt")


def test_traversal_that_would_cancel_out_is_still_rejected(sandbox):
    """Even a path that resolves back inside is refused, not normalised."""
    with pytest.raises(workspace.PathNotAllowed, match="traversal"):
        workspace.resolve_path("customers/../customers/orders.json")


def test_absolute_path_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="Absolute"):
        workspace.resolve_path("/etc/passwd")


def test_home_relative_path_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.resolve_path("~/.ssh/id_rsa")


def test_backslash_traversal_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="traversal"):
        workspace.resolve_path("..\\..\\secret.txt")


def test_empty_path_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.resolve_path("   ")


def test_null_byte_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed, match="null byte"):
        workspace.resolve_path("customers/orders.json\x00.txt")


def test_a_non_string_path_is_rejected(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.resolve_path(None)


# ---------------------------------------------------------------------------
# The vault and the app database are unreachable
# ---------------------------------------------------------------------------


def test_the_registry_cannot_be_reached_through_a_workspace_path(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.resolve_path("../vault/registry.db")


def test_the_app_database_cannot_be_reached_through_a_workspace_path(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.resolve_path("../data/app.db")


def test_reading_the_registry_through_a_path_is_refused(sandbox):
    with pytest.raises(workspace.PathNotAllowed):
        workspace.read_file("../vault/registry.db")


def test_the_real_vault_is_not_inside_the_real_workspace():
    root = workspace.workspace_root()

    assert root not in config.REGISTRY_DB.resolve().parents
    assert root not in config.APP_DB.resolve().parents


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------


def test_a_symlink_to_a_file_outside_is_rejected(sandbox):
    link = config.WORKSPACE_DIR / "customers" / "leak.txt"
    link.symlink_to(sandbox / "secret.txt")

    with pytest.raises(workspace.PathNotAllowed, match="Symbolic links"):
        workspace.resolve_path("customers/leak.txt")


def test_a_symlinked_directory_is_rejected(sandbox):
    link = config.WORKSPACE_DIR / "elsewhere"
    link.symlink_to(sandbox / "vault", target_is_directory=True)

    with pytest.raises(workspace.PathNotAllowed, match="Symbolic links"):
        workspace.resolve_path("elsewhere/registry.db")


def test_a_symlink_pointing_inside_the_workspace_is_also_rejected(sandbox):
    """Refused on shape, without inspecting where it leads."""
    link = config.WORKSPACE_DIR / "customers" / "alias.json"
    link.symlink_to(config.WORKSPACE_DIR / "customers" / "orders.json")

    with pytest.raises(workspace.PathNotAllowed, match="Symbolic links"):
        workspace.resolve_path("customers/alias.json")


# ---------------------------------------------------------------------------
# Missing resources and the read cap
# ---------------------------------------------------------------------------


def test_a_missing_file_raises_not_found(sandbox):
    with pytest.raises(workspace.ResourceNotFound):
        workspace.read_file("customers/nothing_here.csv")


def test_a_missing_folder_raises_not_found(sandbox):
    with pytest.raises(workspace.ResourceNotFound):
        workspace.list_folder("marketing")


def test_reading_a_folder_as_a_file_raises_not_found(sandbox):
    with pytest.raises(workspace.ResourceNotFound):
        workspace.read_file("customers")


def test_a_file_over_1mb_is_refused(sandbox):
    big = config.WORKSPACE_DIR / "customers" / "huge.csv"
    big.write_text("x" * (workspace.MAX_READ_BYTES + 1), encoding="utf-8")

    with pytest.raises(workspace.FileTooLarge, match="read limit"):
        workspace.read_file("customers/huge.csv")


def test_a_file_at_exactly_the_cap_is_allowed(sandbox):
    edge = config.WORKSPACE_DIR / "customers" / "exact.csv"
    edge.write_text("x" * workspace.MAX_READ_BYTES, encoding="utf-8")

    assert len(workspace.read_file("customers/exact.csv")) == workspace.MAX_READ_BYTES


def test_relative_name_is_used_for_audit_references(sandbox):
    path = workspace.resolve_path("customers/orders.json")

    assert workspace.relative_name(path) == "workspace/customers/orders.json"

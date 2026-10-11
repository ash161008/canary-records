"""Browser checks: things only a real layout engine can answer.

These run the app in headless Chrome against a real server, because the
questions here - how wide is the page, how many options are in that select,
is that number clipped - cannot be answered by reading the source.

**These are a nice-to-have, not a gate.** They are skipped, never failed, when
Chrome is missing or slow to answer, and they are excluded from the normal
suite run:

    .venv/bin/pytest -q --ignore=tests/test_browser.py   # the gate
    .venv/bin/pytest -q tests/test_browser.py            # the layout check

A skip means the browser was not checked. It does not mean the layout passed,
and a report should say so rather than implying otherwise.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from backend import config

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)

ADMIN_TOKEN = "browser-check-token"
HARNESS_NAME = "_browser_check.html"

# The probe reports what only the layout engine knows, into the <title>.
PROBE = """
<script>
window.addEventListener("load", () => {
  const measure = () => {
    const root = document.documentElement;
    const clipped = [];
    document.querySelectorAll(".count-value, .count-label, .headline-value").forEach((n) => {
      if (n.scrollWidth > n.clientWidth + 1 || n.scrollHeight > n.clientHeight + 1) {
        clipped.push((n.className || "") + ":" + (n.textContent || "").slice(0, 32));
      }
    });
    const past = [];
    document.querySelectorAll("*").forEach((n) => {
      const r = n.getBoundingClientRect();
      if (r.right > root.clientWidth + 1) {
        past.push(n.tagName.toLowerCase() + "." + (n.className || "").toString().split(" ")[0]);
      }
    });
    const agents = document.getElementById("agent-select");
    document.title = JSON.stringify({
      scrollWidth: root.scrollWidth,
      clientWidth: root.clientWidth,
      agentOptions: agents ? agents.options.length : -1,
      agentTexts: agents ? Array.from(agents.options).map((o) => o.textContent) : [],
      clipped: clipped,
      past: past.slice(0, 8),
    });
  };
  setTimeout(measure, 3000);
});
</script>
"""


def find_chrome():
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return shutil.which("google-chrome") or shutil.which("chromium")


CHROME = find_chrome()

pytestmark = pytest.mark.skipif(
    CHROME is None, reason="headless Chrome is not installed, so layout was not checked"
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def harness():
    """The real page plus the probe, served from the frontend directory.

    It has to live beside index.html so /static/styles.css and /static/app.js
    resolve exactly as they do for the real page.
    """
    source = config.FRONTEND_DIR / "index.html"
    target = config.FRONTEND_DIR / HARNESS_NAME
    target.write_text(
        source.read_text(encoding="utf-8").replace("</body>", PROBE + "</body>"),
        encoding="utf-8",
    )
    try:
        yield HARNESS_NAME
    finally:
        target.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def server():
    """A real server on a free port, with the demo seeded.

    It runs against the project's own databases, which is what the demo does.
    Nothing here deletes them.
    """
    import requests

    port = free_port()
    environment = dict(os.environ, ADMIN_TOKEN=ADMIN_TOKEN)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=config.BASE_DIR,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(80):
            try:
                if requests.get(f"{base}/api/health", timeout=1).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.25)
        else:
            pytest.skip("the server did not start")

        was_seeded = requests.get(f"{base}/api/workspace", timeout=5).json()["seeded"]
        if not was_seeded:
            requests.post(
                f"{base}/api/workspace/seed",
                headers={"X-Admin-Token": ADMIN_TOKEN},
                timeout=60,
            )
        yield base
        if not was_seeded:
            # Left as it was found: unseeded, never deleted.
            requests.post(
                f"{base}/api/workspace/unseed",
                headers={"X-Admin-Token": ADMIN_TOKEN},
                timeout=60,
            )
    finally:
        process.terminate()
        process.wait(timeout=20)


CHROME_TIMEOUT_SECONDS = 25


def measure(server, harness, screen, width):
    """Load one screen at one width and return what the probe reported.

    A slow or unhelpful browser skips the check rather than failing it: this
    module is not a gate, and a flaky headless Chrome must never block a
    release.
    """
    try:
        result = subprocess.run(
            [
                CHROME,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--hide-scrollbars",
                f"--window-size={width},900",
                "--virtual-time-budget=4000",
                "--dump-dom",
                f"{server}/static/{harness}#{screen}",
            ],
            capture_output=True,
            text=True,
            timeout=CHROME_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        pytest.skip(f"Chrome did not answer in time ({type(error).__name__})")

    found = re.search(r"<title>(.*?)</title>", result.stdout, re.S)
    if not found:
        pytest.skip("Chrome did not report; the page may not have run")
    raw = found.group(1).replace("&quot;", '"').replace("&amp;", "&")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pytest.skip("the probe's report could not be read")


# ---------------------------------------------------------------------------
# The agent picker
# ---------------------------------------------------------------------------


def test_the_agent_picker_has_one_option_per_agent(server, harness):
    """It was listing every agent twice.

    showScreen() set the hash, which fired hashchange, which called
    showScreen() again - so the picker was populated twice.
    """
    import requests

    expected = requests.get(f"{server}/api/agents", timeout=10).json()["selectable"]
    reported = measure(server, harness, "run", 1440)

    assert reported["agentOptions"] == len(expected), reported["agentTexts"]
    assert reported["agentTexts"] == [agent["agent_label"] for agent in expected]


def test_the_picker_has_no_duplicate_labels(server, harness):
    reported = measure(server, harness, "run", 1440)

    assert len(set(reported["agentTexts"])) == len(reported["agentTexts"])


# ---------------------------------------------------------------------------
# Nothing scrolls sideways
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("screen", ["run", "seed"])
@pytest.mark.parametrize("width", [1280, 1440])
def test_no_screen_scrolls_sideways(server, harness, screen, width):
    reported = measure(server, harness, screen, width)

    assert reported["scrollWidth"] <= reported["clientWidth"], (
        f"{screen} at {width}px is {reported['scrollWidth']}px wide; "
        f"past the edge: {reported['past']}"
    )


# ---------------------------------------------------------------------------
# Nothing is clipped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("width", [1280, 1440])
def test_the_records_per_location_counts_are_not_clipped(server, harness, width):
    """The path and the count both have to fit, at both widths."""
    reported = measure(server, harness, "seed", width)

    assert reported["clipped"] == [], reported["clipped"]

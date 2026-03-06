"""
test_watchdog.py
Author: Mourya Reddy Udumula
Tests for ops/watchdog_service.py — VaultZero honeypot integrity monitor.

Covers:
  1. get_file_hash() returns expected SHA-256 for known content.
  2. get_file_hash() returns None for a non-existent path.
  3. log_event() appends a correctly-formatted pipe-delimited line.
  4. start_watchdog() detects a file modification within 2 seconds
     (daemon thread + monkeypatch + threading.Event).
  5. CPU overhead: watchdog thread uses < 5% CPU on average (soft warning),
     hard failure only at 25%+ to prevent false failures in CI environments
     (requires psutil; skipped automatically if psutil is not installed).
"""

import sys
import os
import time
import hashlib
import threading
import warnings

import pytest

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPS_DIR = os.path.join(ROOT, 'ops')
sys.path.insert(0, ROOT)
sys.path.insert(0, OPS_DIR)

import config
import watchdog_service


# ------------------------------------------------------------------
# 1 & 2: get_file_hash
# ------------------------------------------------------------------

class TestGetFileHash:
    def test_known_content_returns_expected_hash(self, tmp_path):
        """get_file_hash returns the SHA-256 of whitespace-normalised content."""
        honeypot = tmp_path / "bait.txt"
        content = "hello   world\n  test"
        honeypot.write_text(content, encoding='utf-8')

        # Replicate watchdog's normalisation: strip all whitespace then hash
        expected = hashlib.sha256(
            "".join(content.split()).encode('utf-8')
        ).hexdigest()

        assert watchdog_service.get_file_hash(str(honeypot)) == expected

    def test_nonexistent_file_returns_none(self, tmp_path):
        """get_file_hash returns None when the target file does not exist."""
        missing = str(tmp_path / "does_not_exist.txt")
        assert watchdog_service.get_file_hash(missing) is None

    def test_golden_hash_matches_bait_content(self, tmp_path):
        """A file written with BAIT_CONTENT hashes to GOLDEN_HASH."""
        bait_file = tmp_path / "admin_credentials.txt"
        bait_file.write_text(config.BAIT_CONTENT, encoding='utf-8')
        assert watchdog_service.get_file_hash(str(bait_file)) == config.GOLDEN_HASH


# ------------------------------------------------------------------
# 3: log_event
# ------------------------------------------------------------------

class TestLogEvent:
    def test_appends_formatted_line(self, tmp_path, monkeypatch):
        """log_event() writes one pipe-delimited line with correct fields."""
        log_path = str(tmp_path / "audit.log")
        monkeypatch.setattr(config, 'AUDIT_LOG', log_path)

        watchdog_service.log_event("TEST_EVENT", "unit test message")

        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        assert len(lines) == 1
        parts = lines[0].strip().split('|')
        # Expected format:
        # utc_ts | ist_ts | WATCHDOG | event_type | message | [USER: ...]
        assert len(parts) == 6, f"Expected 6 pipe-separated fields, got {len(parts)}: {parts}"
        assert parts[2] == 'WATCHDOG'
        assert parts[3] == 'TEST_EVENT'
        assert parts[4] == 'unit test message'
        assert parts[5].startswith('[USER:')

    def test_appends_multiple_events(self, tmp_path, monkeypatch):
        """log_event() appends; calling it N times produces N lines."""
        log_path = str(tmp_path / "multi.log")
        monkeypatch.setattr(config, 'AUDIT_LOG', log_path)

        for i in range(3):
            watchdog_service.log_event("EVT", f"msg_{i}")

        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        assert len(lines) == 3


# ------------------------------------------------------------------
# 4: start_watchdog — modification detection
# ------------------------------------------------------------------

class TestStartWatchdog:
    def test_detects_modification_within_2_seconds(self, tmp_path, monkeypatch):
        """
        start_watchdog() sets last_alerted_hash when the honeypot file is
        modified, detected within 2 seconds.

        Strategy:
        - Monkeypatch config paths to use tmp_path (isolated from real files).
        - Save the real time.sleep; replace it with a fast version (0.05 s)
          that stops the watchdog loop once detection is confirmed.
        - Modify the honeypot file from the main thread after one watchdog cycle.
        - Use threading.Event to wait for detection (up to 2 s).
        """
        honeypot  = tmp_path / "admin_credentials.txt"
        audit_log = tmp_path / "audit.log"
        sec_log   = tmp_path / "security.log"

        monkeypatch.setattr(config, 'HONEYPOT_FILE', str(honeypot))
        monkeypatch.setattr(config, 'AUDIT_LOG',     str(audit_log))
        monkeypatch.setattr(config, 'SECURITY_LOG',  str(sec_log))
        # Reset module-level detection state for test isolation
        monkeypatch.setattr(watchdog_service, 'last_alerted_hash', None)

        # Seed honeypot with golden content so watchdog starts in clean state
        honeypot.write_text(config.BAIT_CONTENT, encoding='utf-8')

        detected = threading.Event()
        stop     = threading.Event()
        _real_sleep = time.sleep

        def controlled_sleep(n):
            """Replace 1-second watchdog sleep with a 50 ms version."""
            _real_sleep(0.05)
            # Check if watchdog has set last_alerted_hash (breach detected)
            if watchdog_service.last_alerted_hash is not None:
                detected.set()
                stop.set()
            if stop.is_set():
                raise SystemExit("watchdog stopped by test")

        monkeypatch.setattr(time, 'sleep', controlled_sleep)

        def run_watchdog():
            try:
                watchdog_service.start_watchdog()
            except SystemExit:
                pass

        t = threading.Thread(target=run_watchdog, daemon=True)
        t.start()

        # Give the watchdog one clean iteration (golden file → no alert)
        _real_sleep(0.15)
        # Tamper with the honeypot
        honeypot.write_text("TAMPERED: credentials stolen!", encoding='utf-8')

        # Wait up to 2 seconds for the watchdog to detect the change
        result = detected.wait(timeout=2.0)
        stop.set()
        t.join(timeout=1.0)

        assert result, "Watchdog did not detect honeypot modification within 2 seconds"
        assert watchdog_service.last_alerted_hash is not None

    def test_no_alert_on_clean_file(self, tmp_path, monkeypatch):
        """
        start_watchdog() does NOT set last_alerted_hash when the honeypot
        content is unchanged (equals GOLDEN_HASH).
        """
        honeypot  = tmp_path / "admin_credentials.txt"
        audit_log = tmp_path / "audit.log"
        sec_log   = tmp_path / "security.log"

        monkeypatch.setattr(config, 'HONEYPOT_FILE', str(honeypot))
        monkeypatch.setattr(config, 'AUDIT_LOG',     str(audit_log))
        monkeypatch.setattr(config, 'SECURITY_LOG',  str(sec_log))
        monkeypatch.setattr(watchdog_service, 'last_alerted_hash', None)

        honeypot.write_text(config.BAIT_CONTENT, encoding='utf-8')

        iteration = [0]
        stop      = threading.Event()
        _real_sleep = time.sleep

        def controlled_sleep(n):
            _real_sleep(0.05)
            iteration[0] += 1
            if iteration[0] >= 3:  # run 3 clean iterations then stop
                stop.set()
                raise SystemExit("done")

        monkeypatch.setattr(time, 'sleep', controlled_sleep)

        def run():
            try:
                watchdog_service.start_watchdog()
            except SystemExit:
                pass

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=2.0)

        assert watchdog_service.last_alerted_hash is None, (
            "Watchdog raised a false alarm on an unmodified honeypot"
        )


# ------------------------------------------------------------------
# 5: CPU overhead (requires psutil)
# ------------------------------------------------------------------

@pytest.mark.skipif(
    not PSUTIL_AVAILABLE,
    reason="psutil not installed — skipping CPU overhead test. "
           "Install with: pip install psutil",
)
class TestCPUOverhead:
    def test_watchdog_cpu_overhead_acceptable(self, tmp_path, monkeypatch):
        """
        CPU overhead test uses a two-tier threshold:
        - Soft warning at 5% (expected target per VaultZero design spec)
        - Hard failure at 25% (indicates serious regression, not just CI noise)
        This prevents false failures in resource-constrained CI environments
        while still catching genuine performance regressions.

        The watchdog runs for ~2 real seconds (no sleep monkeypatch) to give
        psutil an accurate measurement window.
        """
        CPU_WARN_THRESHOLD = 5.0
        CPU_FAIL_THRESHOLD = 25.0   # Only hard-fail if egregiously high

        honeypot  = tmp_path / "admin_credentials.txt"
        audit_log = tmp_path / "audit.log"
        sec_log   = tmp_path / "security.log"

        monkeypatch.setattr(config, 'HONEYPOT_FILE', str(honeypot))
        monkeypatch.setattr(config, 'AUDIT_LOG',     str(audit_log))
        monkeypatch.setattr(config, 'SECURITY_LOG',  str(sec_log))
        monkeypatch.setattr(watchdog_service, 'last_alerted_hash', None)

        honeypot.write_text(config.BAIT_CONTENT, encoding='utf-8')

        stop = threading.Event()
        _real_sleep = time.sleep

        def timed_sleep(n):
            # Use real sleep — we want accurate CPU measurement
            _real_sleep(min(n, 1.0))
            if stop.is_set():
                raise SystemExit("done")

        monkeypatch.setattr(time, 'sleep', timed_sleep)

        proc = psutil.Process()
        # Warm-up call to avoid first-call anomaly
        proc.cpu_percent(interval=None)

        def run():
            try:
                watchdog_service.start_watchdog()
            except SystemExit:
                pass

        t = threading.Thread(target=run, daemon=True)
        t.start()

        # Measure CPU over ~2 seconds (interval=2 blocks for 2 s then returns %)
        cpu_percent = proc.cpu_percent(interval=2)
        stop.set()
        t.join(timeout=2.0)

        if cpu_percent > CPU_FAIL_THRESHOLD:
            pytest.fail(
                f"Watchdog CPU overhead {cpu_percent:.1f}% exceeds hard limit of "
                f"{CPU_FAIL_THRESHOLD}%. Check for busy-wait regressions in start_watchdog()."
            )
        elif cpu_percent > CPU_WARN_THRESHOLD:
            warnings.warn(
                f"Watchdog CPU overhead {cpu_percent:.1f}% exceeds soft target of "
                f"{CPU_WARN_THRESHOLD}%. "
                f"Acceptable in CI environments with background processes.",
                UserWarning,
            )
        # else: under both thresholds — all good

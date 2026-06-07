# =============================================================================
# database/db.py — SQLite Database Layer
# =============================================================================
# This is the ONLY file that talks to the database.
# Every other module imports functions from here.
#
# Tables:
#   visitors    → tracks every IP that connects to the proxy
#   blocked_ips → permanent block list with attack details
#   alerts      → audit log of every admin email alert
# =============================================================================

import sqlite3
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

# Import the database path from central config
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DB_PATH

# Set up a logger for this module
# All DB errors will be printed with a [database] prefix
logger = logging.getLogger("database")


# =============================================================================
# CONNECTION HELPER
# =============================================================================

@contextmanager
def get_connection():
    """
    Context manager that opens a SQLite connection and guarantees it's
    properly closed — even if an error occurs.

    Usage:
        with get_connection() as conn:
            conn.execute("SELECT ...")

    Why context manager?
    → Prevents forgetting to close connections (resource leak).
    → Automatically rolls back on error, commits on success.
    """
    conn = sqlite3.connect(DB_PATH)

    # Return rows as dictionaries (access by column name, not index)
    # e.g. row["ip_address"] instead of row[0]
    conn.row_factory = sqlite3.Row

    try:
        yield conn
        conn.commit()   # Save changes if everything went fine
    except Exception as e:
        conn.rollback() # Undo changes if anything went wrong
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()    # Always close the connection


# =============================================================================
# TABLE CREATION
# =============================================================================

def init_db():
    """
    Creates all database tables if they don't already exist.
    Safe to call multiple times — won't overwrite existing data.

    Call this once when the proxy server starts up.
    """
    with get_connection() as conn:

        # ------------------------------------------------------------------
        # Table 1: visitors
        # Tracks every unique IP address that connects to the proxy.
        # We UPSERT (insert or update) on each request from a known IP.
        # ------------------------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                ip_address  TEXT PRIMARY KEY,   -- unique IP (e.g. "192.168.1.1")
                first_seen  TEXT NOT NULL,       -- ISO timestamp of first request
                last_seen   TEXT NOT NULL,       -- ISO timestamp of latest request
                visit_count INTEGER DEFAULT 1   -- total requests from this IP
            )
        """)

        # ------------------------------------------------------------------
        # Table 2: blocked_ips
        # Every blocked request is recorded here.
        # An IP can appear multiple times (each attack attempt logged).
        # ------------------------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address   TEXT NOT NULL,       -- the blocked IP
                attack_type  TEXT NOT NULL,       -- e.g. "SQL Injection", "Zero-Day"
                block_reason TEXT NOT NULL,       -- human-readable explanation
                timestamp    TEXT NOT NULL        -- when the block happened
            )
        """)

        # ------------------------------------------------------------------
        # Table 3: alerts
        # Audit log of admin email notifications.
        # Lets us track if emails were sent successfully.
        # ------------------------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type  TEXT NOT NULL,       -- attack class
                ip_address   TEXT NOT NULL,       -- source IP
                email_status TEXT NOT NULL,       -- "sent" or "failed"
                timestamp    TEXT NOT NULL        -- when alert was created
            )
        """)

    logger.info("Database initialized — all tables ready.")


# =============================================================================
# VISITOR FUNCTIONS
# =============================================================================

def log_visitor(ip_address: str):
    """
    Record a visit from an IP address.

    - If this IP is new → insert a fresh row.
    - If this IP visited before → update last_seen and increment visit_count.

    This uses SQLite's "INSERT OR REPLACE" with a trick to preserve
    the original first_seen date even on updates.

    Args:
        ip_address: The IP string, e.g. "203.0.113.42"
    """
    now = _now()

    with get_connection() as conn:
        # Check if we've seen this IP before
        existing = conn.execute(
            "SELECT first_seen, visit_count FROM visitors WHERE ip_address = ?",
            (ip_address,)
        ).fetchone()

        if existing:
            # IP already known → update the record
            conn.execute("""
                UPDATE visitors
                SET last_seen   = ?,
                    visit_count = visit_count + 1
                WHERE ip_address = ?
            """, (now, ip_address))
        else:
            # New IP → create a fresh record
            conn.execute("""
                INSERT INTO visitors (ip_address, first_seen, last_seen, visit_count)
                VALUES (?, ?, ?, 1)
            """, (ip_address, now, now))


def get_all_visitors(limit: int = 500):
    """
    Fetch all visitor records, ordered by most recent activity.

    Args:
        limit: Maximum rows to return (avoids huge memory usage)

    Returns:
        List of dicts with keys: ip_address, first_seen, last_seen, visit_count
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT ip_address, first_seen, last_seen, visit_count
            FROM visitors
            ORDER BY last_seen DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# =============================================================================
# BLOCKED IP FUNCTIONS
# =============================================================================

def is_ip_blocked(ip_address: str) -> bool:
    """
    Check if an IP is on the block list.

    This is checked FIRST on every incoming request — before any ML runs.
    Known bad actors are instantly rejected without consuming compute.

    Args:
        ip_address: IP string to check

    Returns:
        True if the IP is blocked, False if it's clean
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM blocked_ips WHERE ip_address = ? LIMIT 1",
            (ip_address,)
        ).fetchone()

    return row is not None


def block_ip(ip_address: str, attack_type: str, block_reason: str):
    """
    Add an IP to the block list and record why it was blocked.

    Args:
        ip_address:   The attacker's IP
        attack_type:  e.g. "SQL Injection", "XSS", "Zero-Day", "DoS"
        block_reason: Human-readable explanation of why it was blocked
    """
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO blocked_ips (ip_address, attack_type, block_reason, timestamp)
            VALUES (?, ?, ?, ?)
        """, (ip_address, attack_type, block_reason, _now()))

    logger.warning(f"Blocked IP {ip_address} | Attack: {attack_type}")


def unblock_ip(ip_address: str) -> int:
    """
    Removes ALL block records for an IP address, effectively whitelisting it.

    After calling this, is_ip_blocked(ip) will return False and the proxy
    will re-inspect future requests from this IP normally.

    Args:
        ip_address: The IP to unblock

    Returns:
        Number of rows deleted (0 if the IP was not blocked)
    """
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM blocked_ips WHERE ip_address = ?",
            (ip_address,)
        )
        deleted = cursor.rowcount

    if deleted > 0:
        logger.info(f"Unblocked IP {ip_address} ({deleted} block record(s) removed)")
    else:
        logger.warning(f"Unblock requested for {ip_address} but no records found")

    return deleted


def search_ip(query: str) -> dict:
    """
    Searches all tables for records matching an IP address (partial match).

    Useful for the dashboard search bar — finds visitor history,
    block events, and alerts for any IP containing the query string.

    Args:
        query: IP string or partial IP (e.g. "192.168" matches all 192.168.x.x)

    Returns:
        Dict with keys:
            visitors: list of visitor records matching the query
            blocked:  list of block events matching the query
            alerts:   list of alert records matching the query
    """
    pattern = f"%{query}%"  # SQL LIKE wildcard on both sides

    with get_connection() as conn:
        visitors = conn.execute(
            """SELECT ip_address, first_seen, last_seen, visit_count
               FROM visitors WHERE ip_address LIKE ?
               ORDER BY last_seen DESC LIMIT 100""",
            (pattern,)
        ).fetchall()

        blocked = conn.execute(
            """SELECT id, ip_address, attack_type, block_reason, timestamp
               FROM blocked_ips WHERE ip_address LIKE ?
               ORDER BY timestamp DESC LIMIT 100""",
            (pattern,)
        ).fetchall()

        alerts = conn.execute(
            """SELECT id, attack_type, ip_address, email_status, timestamp
               FROM alerts WHERE ip_address LIKE ?
               ORDER BY timestamp DESC LIMIT 100""",
            (pattern,)
        ).fetchall()

    return {
        "visitors": [dict(r) for r in visitors],
        "blocked":  [dict(r) for r in blocked],
        "alerts":   [dict(r) for r in alerts],
    }


def get_blocked_ips(limit: int = 500):
    """
    Fetch all blocked IP records, newest first.

    Returns:
        List of dicts with keys: id, ip_address, attack_type, block_reason, timestamp
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, ip_address, attack_type, block_reason, timestamp
            FROM blocked_ips
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# =============================================================================
# ALERT FUNCTIONS
# =============================================================================

def log_alert(attack_type: str, ip_address: str, email_status: str):
    """
    Record that an admin alert was generated for a blocked request.

    Args:
        attack_type:   The detected attack class
        ip_address:    Source IP
        email_status:  "sent" if email delivered, "failed" if SMTP error
    """
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alerts (attack_type, ip_address, email_status, timestamp)
            VALUES (?, ?, ?, ?)
        """, (attack_type, ip_address, email_status, _now()))


def get_recent_alerts(limit: int = 50):
    """
    Fetch the most recent alert records for the dashboard.

    Args:
        limit: How many records to return

    Returns:
        List of dicts with keys: id, attack_type, ip_address, email_status, timestamp
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, attack_type, ip_address, email_status, timestamp
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# =============================================================================
# STATISTICS (for Dashboard)
# =============================================================================

def get_stats() -> dict:
    """
    Returns summary counts used in the dashboard overview panel.

    Returns a dict with:
        total_requests  → total rows in visitors (all-time request count)
        unique_visitors → number of distinct IPs seen
        blocked_count   → number of block events recorded
        attack_attempts → same as blocked_count (alias for clarity)
    """
    with get_connection() as conn:

        # Total number of requests ever received (sum of all visit counts)
        total_requests = conn.execute(
            "SELECT COALESCE(SUM(visit_count), 0) FROM visitors"
        ).fetchone()[0]

        # Number of unique IP addresses seen
        unique_visitors = conn.execute(
            "SELECT COUNT(*) FROM visitors"
        ).fetchone()[0]

        # Total block events
        blocked_count = conn.execute(
            "SELECT COUNT(*) FROM blocked_ips"
        ).fetchone()[0]

        # Number of unique IPs that were blocked
        unique_blocked_ips = conn.execute(
            "SELECT COUNT(DISTINCT ip_address) FROM blocked_ips"
        ).fetchone()[0]

    return {
        "total_requests":    total_requests,
        "unique_visitors":   unique_visitors,
        "blocked_count":     blocked_count,
        "attack_attempts":   blocked_count,        # alias
        "unique_blocked_ips": unique_blocked_ips,
    }


def get_attack_distribution() -> list:
    """
    Returns attack type counts for the pie/bar chart in the dashboard.

    Returns:
        List of dicts: [{"attack_type": "SQL Injection", "count": 42}, ...]
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM blocked_ips
            GROUP BY attack_type
            ORDER BY count DESC
        """).fetchall()

    return [dict(row) for row in rows]


def get_daily_attack_counts() -> list:
    """
    Returns per-day attack counts for the time series chart.

    Extracts just the date portion (YYYY-MM-DD) from the timestamp.

    Returns:
        List of dicts: [{"date": "2024-01-15", "count": 7}, ...]
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT SUBSTR(timestamp, 1, 10) as date, COUNT(*) as count
            FROM blocked_ips
            GROUP BY date
            ORDER BY date ASC
        """).fetchall()

    return [dict(row) for row in rows]


def get_top_attacker_ips(limit: int = 10) -> list:
    """
    Returns the IPs with the most attack attempts.

    Args:
        limit: How many top IPs to return

    Returns:
        List of dicts: [{"ip_address": "1.2.3.4", "attempts": 15}, ...]
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT ip_address, COUNT(*) as attempts
            FROM blocked_ips
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# =============================================================================
# INTERNAL HELPERS
# =============================================================================

def _now() -> str:
    """
    Returns the current UTC time as an ISO 8601 string.
    Example: "2024-01-15T10:30:00+00:00"

    Using UTC ensures consistent timestamps regardless of server timezone.
    """
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# QUICK SELF-TEST
# Run this file directly to verify the database works:
#   python database/db.py
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=" * 60)
    print("Running database self-test...")
    print("=" * 60)

    # Step 1: Initialize tables
    init_db()
    print("✓ Tables created")

    # Step 2: Log some fake visitors
    log_visitor("192.168.1.10")
    log_visitor("192.168.1.10")  # Second visit — should increment count
    log_visitor("10.0.0.5")
    print("✓ Visitors logged")

    # Step 3: Check visitor records
    visitors = get_all_visitors()
    for v in visitors:
        print(f"  Visitor: {v['ip_address']} | Visits: {v['visit_count']}")

    # Step 4: Block an IP
    block_ip(
        ip_address="10.0.0.5",
        attack_type="SQL Injection",
        block_reason="Request contained SQL keywords: SELECT, UNION, DROP"
    )
    print("✓ IP blocked")

    # Step 5: Check if IP is blocked
    print(f"  Is 10.0.0.5 blocked? {is_ip_blocked('10.0.0.5')}")
    print(f"  Is 192.168.1.10 blocked? {is_ip_blocked('192.168.1.10')}")

    # Step 6: Log an alert
    log_alert("SQL Injection", "10.0.0.5", "sent")
    print("✓ Alert logged")

    # Step 7: Check stats
    stats = get_stats()
    print(f"✓ Stats: {stats}")

    # Step 8: Attack distribution
    dist = get_attack_distribution()
    print(f"✓ Attack distribution: {dist}")

    print("=" * 60)
    print("All tests passed! Database is working correctly.")
    print(f"Database file: {DB_PATH}")
    print("=" * 60)

    # Clean up test database file
    import os
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("(Test database cleaned up)")
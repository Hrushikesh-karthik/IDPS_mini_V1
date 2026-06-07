# =============================================================================
# dashboard/dashboard.py — Live Security Monitoring Dashboard
# =============================================================================
# Run with:
#   streamlit run dashboard/dashboard.py
#
# New features in this version:
#   • IP Search bar — search across visitors, blocks, and alerts
#   • Unblock IP  — remove an IP from the block list with one click
#   • Live Traffic tab — real-time packet feed from the proxy log file
# =============================================================================

import sys
import os
import time
import json
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database.db import (
    get_stats, get_all_visitors, get_blocked_ips,
    get_recent_alerts, get_attack_distribution,
    get_daily_attack_counts, get_top_attacker_ips,
    unblock_ip, search_ip
)
from config import TRAFFIC_LOG_PATH, TRAFFIC_LOG_DISPLAY_LINES

# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="Zero Trust Proxy — Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.title("🛡️ Zero Trust Proxy")
    st.caption("AI-Powered Security Dashboard")
    st.divider()

    auto_refresh = st.toggle("Auto Refresh (5s)", value=False)
    if auto_refresh:
        time.sleep(5)
        st.rerun()

    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

    st.divider()

    # --- IP Search (sidebar so it's always visible) ---
    st.markdown("### 🔍 IP Search")
    search_query = st.text_input(
        "Search IP address",
        placeholder="e.g. 192.168 or 10.0.0.1",
        label_visibility="collapsed"
    )

    if search_query.strip():
        results = search_ip(search_query.strip())
        total_hits = (
            len(results["visitors"]) +
            len(results["blocked"]) +
            len(results["alerts"])
        )
        st.caption(f"{total_hits} result(s) for `{search_query}`")

        if results["visitors"]:
            st.markdown("**Visitor records**")
            for v in results["visitors"][:5]:
                blocked_marker = "🚫 " if any(
                    b["ip_address"] == v["ip_address"]
                    for b in results["blocked"]
                ) else "✅ "
                st.text(f"{blocked_marker}{v['ip_address']} ({v['visit_count']} visits)")

        if results["blocked"]:
            st.markdown("**Block events**")
            for b in results["blocked"][:5]:
                st.text(f"🔴 {b['ip_address']} — {b['attack_type']}")

        if not results["visitors"] and not results["blocked"]:
            st.info("No records found.")

    st.divider()
    st.caption("Proxy: :8000 | Dashboard: :8501")
    st.caption(f"Log: {os.path.basename(TRAFFIC_LOG_PATH)}")


# =============================================================================
# MAIN TABS
# =============================================================================

st.title("🛡️ Zero Trust AI Security Proxy")
st.caption("Real-time monitoring of incoming traffic and blocked attacks.")

main_tab1, main_tab2, main_tab3 = st.tabs([
    "📊 Overview & Analytics",
    "📋 IP Management",
    "📡 Live Traffic"
])


# =============================================================================
# TAB 1: OVERVIEW & ANALYTICS
# =============================================================================

with main_tab1:

    # --- KPI Metrics ---
    stats = get_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests",  f"{stats['total_requests']:,}")
    c2.metric("Unique Visitors", f"{stats['unique_visitors']:,}")
    c3.metric("Blocked IPs",     f"{stats['unique_blocked_ips']:,}")
    c4.metric("Attack Attempts", f"{stats['attack_attempts']:,}")

    st.divider()
    st.subheader("📈 Attack Analytics")

    col_a, col_b = st.columns(2)

    # Attack distribution donut
    with col_a:
        st.markdown("**Attack Type Distribution**")
        dist = get_attack_distribution()
        if dist:
            df_dist = pd.DataFrame(dist)
            fig = px.pie(
                df_dist, names="attack_type", values="count",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(margin=dict(t=0,b=0,l=0,r=0), height=320,
                              showlegend=True,
                              legend=dict(orientation="v", x=1.0, y=0.5))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks recorded yet.")

    # Daily attack timeline
    with col_b:
        st.markdown("**Daily Attack Count**")
        daily = get_daily_attack_counts()
        if daily:
            df_daily = pd.DataFrame(daily)
            fig = px.bar(
                df_daily, x="date", y="count",
                color="count", color_continuous_scale="Reds",
                labels={"date": "Date", "count": "Attacks"}
            )
            fig.update_layout(coloraxis_showscale=False,
                              margin=dict(t=0,b=40,l=40,r=0), height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timeline data yet.")

    # Top attacker IPs
    st.markdown("**Top Attacker IPs**")
    top = get_top_attacker_ips(limit=10)
    if top:
        df_top = pd.DataFrame(top)
        fig = px.bar(
            df_top, x="attempts", y="ip_address", orientation="h",
            color="attempts", color_continuous_scale="OrRd",
            labels={"attempts": "Attack Attempts", "ip_address": "IP Address"}
        )
        fig.update_layout(
            yaxis=dict(autorange="reversed"),
            coloraxis_showscale=False,
            margin=dict(t=0,b=40,l=120,r=0),
            height=max(200, len(top) * 40)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attacker IP data yet.")


# =============================================================================
# TAB 2: IP MANAGEMENT (Visitors + Blocked IPs + Alerts + Unblock)
# =============================================================================

with main_tab2:

    sub1, sub2, sub3 = st.tabs([
        "🌐 Visitor History",
        "🚫 Blocked IPs & Unblock",
        "🔔 Recent Alerts"
    ])

    # --- Visitor History ---
    with sub1:
        st.markdown("#### Visitor History")

        # Search filter
        vis_search = st.text_input(
            "Filter by IP", placeholder="Type to filter...",
            key="vis_search"
        )

        visitors = get_all_visitors(limit=500)
        blocked_set = set(
            r["ip_address"] for r in get_blocked_ips(limit=99999)
        )

        if visitors:
            df = pd.DataFrame(visitors)
            df["Status"] = df["ip_address"].apply(
                lambda ip: "🚫 Blocked" if ip in blocked_set else "✅ Allowed"
            )
            df = df.rename(columns={
                "ip_address":  "IP Address",
                "visit_count": "Visits",
                "first_seen":  "First Seen",
                "last_seen":   "Last Seen"
            })[["IP Address", "Status", "Visits", "First Seen", "Last Seen"]]

            if vis_search.strip():
                df = df[df["IP Address"].str.contains(vis_search.strip(), na=False)]

            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(df)} record(s)")
        else:
            st.info("No visitor records yet.")

    # --- Blocked IPs with Unblock ---
    with sub2:
        st.markdown("#### Blocked IPs")
        st.caption(
            "Use the search box to find an IP, then click **Unblock** "
            "to remove it from the block list."
        )

        # Search filter
        blk_search = st.text_input(
            "Filter blocked IPs", placeholder="e.g. 10.0.0",
            key="blk_search"
        )

        blocked = get_blocked_ips(limit=500)

        if blocked:
            # Group by IP — show each unique IP once with an unblock button
            # Build a deduplicated view
            seen_ips = {}
            for row in blocked:
                ip = row["ip_address"]
                if ip not in seen_ips:
                    seen_ips[ip] = {
                        "ip_address":  ip,
                        "attack_types": set(),
                        "block_count":  0,
                        "latest":       row["timestamp"],
                        "last_reason":  row["block_reason"],
                    }
                seen_ips[ip]["attack_types"].add(row["attack_type"])
                seen_ips[ip]["block_count"] += 1
                if row["timestamp"] > seen_ips[ip]["latest"]:
                    seen_ips[ip]["latest"]      = row["timestamp"]
                    seen_ips[ip]["last_reason"]  = row["block_reason"]

            ip_rows = list(seen_ips.values())

            # Apply filter
            if blk_search.strip():
                ip_rows = [r for r in ip_rows if blk_search.strip() in r["ip_address"]]

            if ip_rows:
                # Render each IP as a row with an Unblock button
                # Use columns: IP | Attack Types | Events | Last Seen | [Unblock]
                hdr = st.columns([2, 2, 1, 2, 1])
                hdr[0].markdown("**IP Address**")
                hdr[1].markdown("**Attack Types**")
                hdr[2].markdown("**Events**")
                hdr[3].markdown("**Last Blocked**")
                hdr[4].markdown("**Action**")
                st.markdown("---")

                for entry in ip_rows:
                    ip   = entry["ip_address"]
                    cols = st.columns([2, 2, 1, 2, 1])
                    cols[0].markdown(f"`{ip}`")
                    cols[1].markdown(", ".join(sorted(entry["attack_types"])))
                    cols[2].markdown(str(entry["block_count"]))
                    cols[3].markdown(entry["latest"][:19].replace("T", " "))

                    # Unblock button — unique key per IP
                    btn_key = f"unblock_{ip.replace('.', '_')}"
                    if cols[4].button("🔓 Unblock", key=btn_key, type="primary"):
                        removed = unblock_ip(ip)
                        if removed:
                            st.success(
                                f"✅ **{ip}** has been unblocked. "
                                f"{removed} block record(s) removed. "
                                "Future requests will be re-inspected."
                            )
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.warning(f"No block records found for {ip}.")
            else:
                st.info("No blocked IPs match the filter.")

        else:
            st.info("No blocked IPs yet. 🎉")

        # Raw block log below the interactive section
        with st.expander("📄 Raw Block Event Log"):
            if blocked:
                df_raw = pd.DataFrame(blocked)
                df_raw = df_raw[["ip_address","attack_type","block_reason","timestamp"]]
                df_raw.columns = ["IP","Attack Type","Reason","Timestamp"]
                df_raw["Reason"] = df_raw["Reason"].str[:100]

                if blk_search.strip():
                    df_raw = df_raw[df_raw["IP"].str.contains(blk_search.strip(), na=False)]

                st.dataframe(df_raw, use_container_width=True, hide_index=True)

    # --- Recent Alerts ---
    with sub3:
        st.markdown("#### Recent Alerts")

        alert_search = st.text_input(
            "Filter alerts by IP", placeholder="e.g. 10.0",
            key="alert_search"
        )

        alerts = get_recent_alerts(limit=100)
        if alerts:
            df_alerts = pd.DataFrame(alerts)
            df_alerts["email_status"] = df_alerts["email_status"].map({
                "sent":     "✅ Sent",
                "failed":   "❌ Failed",
                "disabled": "⏸️ Disabled"
            }).fillna(df_alerts["email_status"])

            df_alerts = df_alerts[["ip_address","attack_type","email_status","timestamp"]]
            df_alerts.columns = ["IP Address","Attack Type","Email","Timestamp"]

            if alert_search.strip():
                df_alerts = df_alerts[
                    df_alerts["IP Address"].str.contains(alert_search.strip(), na=False)
                ]

            st.dataframe(df_alerts, use_container_width=True, hide_index=True)
            st.caption(f"{len(df_alerts)} alert(s)")
        else:
            st.info("No alerts yet.")


# =============================================================================
# TAB 3: LIVE TRAFFIC FEED
# =============================================================================

with main_tab3:

    st.markdown("#### 📡 Live Traffic Packets")
    st.caption(
        "Every request hitting the proxy appears here in real time. "
        "Green = allowed through. Red = blocked. "
        "Enable Auto Refresh in the sidebar for a live feed."
    )

    # Controls row
    ctrl1, ctrl2, ctrl3 = st.columns([1, 1, 2])
    show_blocked_only = ctrl1.toggle("Blocked only", value=False)
    show_allowed_only = ctrl2.toggle("Allowed only", value=False)
    traffic_search    = ctrl3.text_input(
        "Filter traffic", placeholder="Filter by IP, URL, method, attack type...",
        label_visibility="collapsed"
    )

    st.divider()

    # Read the traffic log file
    entries = []

    if os.path.exists(TRAFFIC_LOG_PATH):
        try:
            with open(TRAFFIC_LOG_PATH, "r") as f:
                lines = f.readlines()

            # Take the most recent N lines
            recent_lines = lines[-TRAFFIC_LOG_DISPLAY_LINES:]

            for line in reversed(recent_lines):  # newest first
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            st.error(f"Could not read traffic log: {e}")
    else:
        st.info(
            f"Traffic log not found at `{TRAFFIC_LOG_PATH}`.\n\n"
            "Start the proxy (`python app.py`) and send some requests — "
            "packets will appear here automatically."
        )

    # Apply filters
    if show_blocked_only:
        entries = [e for e in entries if e.get("status") == "BLOCKED"]
    if show_allowed_only:
        entries = [e for e in entries if e.get("status") == "ALLOWED"]
    if traffic_search.strip():
        q = traffic_search.strip().lower()
        entries = [
            e for e in entries
            if q in e.get("ip", "").lower()
            or q in e.get("url", "").lower()
            or q in e.get("method", "").lower()
            or q in e.get("attack_type", "").lower()
            or q in e.get("user_agent", "").lower()
        ]

    # Summary row
    if entries:
        total   = len(entries)
        blocked = sum(1 for e in entries if e.get("status") == "BLOCKED")
        allowed = total - blocked
        sm1, sm2, sm3 = st.columns(3)
        sm1.metric("Packets shown", total)
        sm2.metric("🔴 Blocked", blocked)
        sm3.metric("🟢 Allowed", allowed)
        st.divider()

    # Render each packet as a card
    if entries:
        for entry in entries:
            is_blocked   = entry.get("status") == "BLOCKED"
            border_color = "#ff4b4b" if is_blocked else "#21c354"
            bg_color     = "#2d1515" if is_blocked else "#152d1f"
            status_icon  = "🔴 BLOCKED" if is_blocked else "🟢 ALLOWED"
            attack_badge = (
                f"&nbsp;&nbsp;`{entry.get('attack_type','?')}`"
                if is_blocked else ""
            )

            # Format timestamp nicely
            ts_raw = entry.get("ts", "")
            try:
                ts = datetime.fromisoformat(ts_raw).strftime("%H:%M:%S")
            except Exception:
                ts = ts_raw[:19]

            # Truncate URL for display
            url_display = entry.get("url", "")
            if len(url_display) > 80:
                url_display = url_display[:77] + "..."

            ua = entry.get("user_agent", "")
            if len(ua) > 70:
                ua = ua[:67] + "..."

            st.markdown(
                f"""
<div style="
    border-left: 4px solid {border_color};
    background: {bg_color};
    border-radius: 6px;
    padding: 10px 16px;
    margin-bottom: 8px;
    font-family: monospace;
    font-size: 13px;
">
<span style="color:{border_color}; font-weight:bold;">{status_icon}</span>
{attack_badge}
&nbsp;&nbsp;
<span style="color:#aaa;">{ts}</span>
&nbsp;&nbsp;
<span style="color:#fff; font-weight:bold;">{entry.get('method','?')}</span>
&nbsp;
<span style="color:#7dd3fc;">{url_display}</span>
<br>
<span style="color:#94a3b8;">
  IP: <b style="color:#e2e8f0;">{entry.get('ip','?')}</b>
  &nbsp;│&nbsp;
  Body: {entry.get('body_size',0)} B
  &nbsp;│&nbsp;
  ⏱ {entry.get('elapsed_ms',0)} ms
  &nbsp;│&nbsp;
  UA: {ua or '—'}
</span>
</div>
""",
                unsafe_allow_html=True
            )
    elif os.path.exists(TRAFFIC_LOG_PATH):
        st.info("No packets match the current filter.")

    st.divider()
    st.caption(
        f"Reading from: `{TRAFFIC_LOG_PATH}` | "
        f"Showing latest {TRAFFIC_LOG_DISPLAY_LINES} packets | "
        "Enable Auto Refresh for live updates."
    )
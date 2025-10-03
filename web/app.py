#!/usr/bin/env python3

import io
import os
import tempfile
import datetime as dt
import streamlit as st
import matplotlib.pyplot as plt

from typing import Dict, List, Tuple
# import analyzer core
import importlib.util, pathlib, sys
core_path = pathlib.Path(__file__).with_name("ai_log_analyzer.py")
spec = importlib.util.spec_from_file_location("ai_core", core_path)
ai_core = importlib.util.module_from_spec(spec)
sys.modules["ai_core"] = ai_core
spec.loader.exec_module(ai_core)  # type: ignore
st.image("logo.png", width=200)
st.set_page_config(page_title="AI Log Analyzer — Mohammed Altanib", layout="wide")
st.title("AI Log Analyzer — by Mohammed Altanib")
st.image("How.gif", width=200)

st.markdown("""
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

st.caption("🔗 https://mohammedaltanib.com  •  Upload an Apache/Nginx access log to analyze suspicious IPs, see charts, and download a report.")

with st.expander("How it works", expanded=False):
    st.markdown("""
- Parses access logs (Common/Combined).
- Scores suspicious behavior (paths, user-agents, HTTP status, bursts).
- Ranks IPs and suggests firewall rules (UFW or iptables).
- Generates charts and a Markdown report you can download.
""")

# Sidebar options
st.sidebar.header("Options")
top_n = st.sidebar.slider("Top IPs", 5, 50, 20, step=1)
use_iptables = st.sidebar.checkbox("Suggest iptables (instead of UFW)", value=False)
show_private = st.sidebar.checkbox("Show private IPs", value=True)
show_per_ip_charts = st.sidebar.checkbox("Per-IP charts for top offenders", value=True)

uploaded = st.file_uploader("Upload access.log", type=["log", "txt"], help="Common/Combined Apache/Nginx access log")
demo = st.checkbox("Use demo log (sample_access.log)", value=False)

log_bytes = None
if demo:
    # load bundled sample
    sample_path = pathlib.Path(__file__).with_name("sample_access.log")
    if sample_path.exists():
        log_bytes = sample_path.read_bytes()
        st.info("Using bundled sample_access.log")
    else:
        st.error("Sample log not found in the app bundle.")
elif uploaded is not None:
    log_bytes = uploaded.read()

if log_bytes is None:
    st.stop()

# Parse lines
lines = log_bytes.decode("utf-8", errors="ignore").splitlines()
entries = []
for line in lines:
    e = ai_core.parse_line(line)
    if e:
        entries.append(e)

if not entries:
    st.error("No valid log lines parsed. Please provide a valid Apache/Nginx access log.")
    st.stop()

# Aggregate and summarize
per_ip = ai_core.aggregate(entries)
ranked = ai_core.summarize(per_ip, top=top_n)

# Optionally filter out private if desired
if not show_private:
    ranked = [(ip, d) for ip, d in ranked if not ai_core.is_private_ip(ip)]

st.subheader("Top Suspicious IPs")
import pandas as pd
rows = []
for i, (ip, d) in enumerate(ranked, 1):
    s401_403 = d['statuses'].get(401,0) + d['statuses'].get(403,0)
    s404 = d['statuses'].get(404,0)
    rows.append({
        "#": i,
        "IP": ip,
        "Final Score": d.get("final_score", 0.0),
        "Requests": d["count"],
        "401/403": s401_403,
        "404": s404,
        "Burst z": d.get("burst_z", 0.0),
        "First Seen": d["first_seen"],
        "Last Seen": d["last_seen"],
        "Private": "Yes" if ai_core.is_private_ip(ip) else "No",
    })
df = pd.DataFrame(rows)
st.dataframe(df, use_container_width=True)

# Overall chart
st.subheader("Overall Requests per Minute")
# build combined timeline
from collections import Counter
total = Counter()
for d in per_ip.values():
    total.update(d["timeline"])
xs = sorted(total.keys())
ys = [total[x] for x in xs]
if xs:
    fig = plt.figure(figsize=(8,3))
    plt.plot(xs, ys)
    plt.title("Overall Requests per Minute")
    plt.xlabel("Time (UTC, minute)")
    plt.ylabel("Requests")
    st.pyplot(fig)
else:
    st.info("No timeline data available.")

# Per-IP charts
if show_per_ip_charts:
    st.subheader("Per-IP Requests (Top Offenders)")
    for ip, d in ranked[:5]:
        xs_ip = sorted(d["timeline"].keys())
        ys_ip = [d["timeline"][x] for x in xs_ip]
        if xs_ip:
            fig2 = plt.figure(figsize=(8,3))
            plt.plot(xs_ip, ys_ip)
            plt.title(f"Requests per Minute — {ip}")
            plt.xlabel("Time (UTC, minute)")
            plt.ylabel("Requests")
            st.pyplot(fig2)

# Suggested commands
st.subheader("Suggested Firewall Rules")
cmds = []
for ip, _ in ranked[:10]:
    cmds.extend(ai_core.suggest_firewall(ip, use_ufw=not use_iptables))
if cmds:
    st.code("\n".join(cmds), language="bash")
else:
    st.info("No commands to suggest.")

# Build a Markdown report and offer as download
st.subheader("Download Report")
tmpdir = tempfile.mkdtemp(prefix="ailog-")
# We reuse core writer but need a path; write to tmpdir
rep_path = ai_core.write_report(per_ip, ranked, outdir=tmpdir, use_ufw=not use_iptables)
with open(rep_path, "r", encoding="utf-8") as f:
    md_bytes = f.read().encode("utf-8")

st.download_button("Download Markdown Report", data=md_bytes, file_name="ai_log_analyzer_report_by_Mohammed_Altanib.md", mime="text/markdown")

st.success("Analysis complete.")

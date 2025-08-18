# AI Log Analyzer — Web UI (Streamlit)

A simple web dashboard for the AI Log Analyzer with **file upload**, **tables**, **charts**, and **downloadable report**.

## Features
- Upload an Apache/Nginx access log file
- See Top Suspicious IPs in a sortable table
- Overall and per-IP request charts (matplotlib)
- Suggested UFW/iptables rules
- Download the Markdown report

## Install & Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt
streamlit run app.py
```
Then open the URL that Streamlit prints (e.g., http://localhost:8501).

Tip: Enable "Use demo log" to try the bundled `sample_access.log`.

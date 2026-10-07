# Honeypot Attack Analytics Platform

A cybersecurity + data analytics project. A Cowrie SSH honeypot collects real
attack traffic, a Python pipeline cleans and enriches it, and a Streamlit
dashboard visualizes attacker behavior with ML-based clustering.

## Features (planned)
- Log ingestion and parsing of Cowrie JSON logs
- SQLite storage with GeoIP enrichment (country, city, ISP)
- Analysis of top usernames/passwords, attack timelines, peak hours
- ML clustering of attacker behavior (scanners vs. bots vs. humans)
- Interactive Streamlit dashboard with an attack map

## Tech Stack
Python, Cowrie, Pandas, SQLite, Scikit-learn, Plotly, Streamlit

## Project Structure
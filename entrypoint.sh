#!/bin/bash

echo "[*] Starting Tor daemon..."
service tor start

# Wait for Tor to bootstrap
sleep 3

echo "[*] Starting Tor IP Rotation Daemon..."
python rotator.py &

echo "[*] Starting Flask Application..."
python app.py

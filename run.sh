#!/bin/bash
# Pastikan sudah chmod +x run.sh
source venv/bin/activate
nohup streamlit run app.py --server.port 8501 > streamlit.log 2>&1 &
echo "Dashboard running in background. Logs: tail -f streamlit.log"

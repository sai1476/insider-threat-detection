# 🔐 Insider Threat Detection via Behavior Analysis

A simple AI-powered system to detect insider threats by analyzing user behavior logs.

## ✨ Features
- Upload CSV logs of user activity
- AI-based anomaly detection (Isolation Forest)
- Risk scoring & explainable alerts
- Secure admin dashboard

##▶️ Demo Credentials
- **Username**: `Admin`
- **Password**: `@admin123`

## 📄 Sample Input Format
| user_id | login_time | files_accessed | usb_inserted | data_transferred_MB |
|---------|------------|----------------|--------------|---------------------|
| emp01   | 22:15      | 72             | 3            | 1680.0              |

> **Note**: Only these columns are required:  
> `user_id`, `files_accessed`, `usb_inserted`, `data_transferred_MB`

## ▶️ How to Run Locally
```bash
pip install -r requirements.txt
python app.py
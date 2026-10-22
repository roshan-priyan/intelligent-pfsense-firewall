# Models

This folder stores the trained ML model files after the system runs.

## Files generated automatically

| File | Description |
|---|---|
| `isolation_forest.pkl` | Trained Isolation Forest model (generated after 20+ collection cycles) |
| `scaler.pkl` | Feature scaler for normalizing input vectors |

## How it works

The `AnomalyDetector` class in `backend/app.py` trains itself
incrementally on each 5-minute window of firewall data.

After 20 windows (100 minutes), the Isolation Forest model becomes
active and replaces the heuristic scoring with ML-based anomaly detection.

The model retrains every 10 windows using the last 200 windows of history.

## Algorithm

- **Model**: Isolation Forest (scikit-learn)
- **Contamination**: 0.1 (10% expected anomaly rate)
- **Feature vector** (8 features):
  1. Total events
  2. Block rate
  3. Unique source IPs
  4. IP entropy (Shannon)
  5. Critical asset hits
  6. Top source IP count
  7. Number of port scan IPs
  8. Number of brute force IPs

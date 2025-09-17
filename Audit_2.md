0. Executive Overview
- Architecture: three-layer detection pipeline composed of Global layer (XGBoost classifier on flow-level volumetric/statistical features), Edge layer (TensorFlow LSTM operating on sequential windows), Device layer (TensorFlow/Keras MLP using behavioral/device-specific attributes), and a static weighted fusion block combining layer confidences (0.3/0.3/0.4) with a 0.5 threshold (`flask_detection/config.py:37-41`, `flask_detection/detection_utils.py:112-117`).
- Runtime stack: Flask detection service (`flask_detection/detection_server.py`) hosting inference endpoints; Node/Express application (`src/app.js`) handling authentication/MFA, static asset serving, and proxying to Flask; MySQL database accessed through `mysql.connector` for persistence; static UI under `public/` retrieving results. This document describes repository state as-is (commit workspace) without proposed changes.

1. Data & Provenance
- Primary dataset referenced at runtime: `INADS_Data/Data/Indexed_Dataset_Cyclical_Encoded.csv` (`flask_detection/config.py:6-14`).
- Dataset origin: CIC-IDS 2018 flow-level records; preprocessing performed in notebooks under `Notebooks/Revised Approach/` (notably `Dataset_Exploration.ipynb`, `Core_Layer.ipynb`, `Edge_Layer.ipynb`, `Device_Layer.ipynb`) including feature selection, normalization experiments, and cyclical encoding for temporal fields (e.g., hour_sin/hour_cos, weekday_sin/weekday_cos). The notebooks depend on engineered CSV outputs stored in `INADS_Data/Data/`.
- Schema assumptions: `run_detection_pipeline` expects columns exactly matching feature lists defined in `flask_detection/config.py:17-34`; columns must be numeric (categorical already encoded). No explicit dtype enforcement occurs—pandas default conversion is relied upon. Column order is implicit—`df[FEATURE_LIST]` slices by name, but the underlying models assume training order aligns with these lists.
- Additional data artifacts: correlation plots (`INADS_Data/Feature_Correlation_*.png`), feature documentation spreadsheets (`INADS_Data/Feature_Documentation.csv/.xlsx`), label encodings (`INADS_Data/Label_Encoder.pkl`) supporting feature engineering.

2. Feature Allocation
- Layer-specific feature definitions sourced from `flask_detection/config.py:17-34`:
  - Global layer: 22 features including flow durations, byte rates, inter-arrival stats, flag counts, packet length extrema, throughput metrics, and temporal cyclical encodings.
  - Edge layer: 7 features focusing on packet length extrema, packet rates, and forward inter-arrival mean, intended for sequential modeling.
  - Device layer: 22 features emphasizing port usage, packet statistics, flow activity/idle metrics, TCP window/header fields, and temporal cyclical encodings.
- Feature table (✓ indicates inclusion in layer model):

  | Feature | Global | Edge | Device | Description |
  | --- | --- | --- | --- | --- |
  | Flow Duration | ✓ |  | ✓ | Session length capturing volumetric anomalies and device dwell time.
  | Flow Byts/s | ✓ |  |  | Aggregate byte rate for volumetric detection.
  | Flow IAT Mean | ✓ |  | ✓ | Inter-arrival mean indicating traffic regularity across flows.
  | Fwd IAT Mean |  | ✓ |  | Forward inter-arrival interval averaged within sequential windows.
  | Flow IAT Std | ✓ |  | ✓ | Variability in packet timing.
  | Flow IAT Max | ✓ |  |  | Max gap to flag stealth/slow behaviors.
  | Dst Port | ✓ |  | ✓ | Encoded destination service information.
  | Protocol | ✓ |  |  | Transport protocol identifier.
  | SYN/ACK/FIN/PSH Flag Count | ✓ |  |  | TCP flag distributions for flow behavior.
  | Pkt Len Min/Max | ✓ | ✓ |  | Packet length extrema for volumetric shifts (Edge uses both extremes).
  | Fwd/Bwd Pkts/s | ✓ | ✓ |  | Directional throughput rates.
  | Fwd Pkt Len Max | ✓ | ✓ | ✓ | Forward payload spikes across layers.
  | Bwd Pkt Len Min | ✓ | ✓ | ✓ | Reverse channel minima.
  | TotLen Fwd/Bwd Pkts | ✓ |  |  | Total bytes per direction.
  | Hour_sin, Hour_cos | ✓ |  | ✓ | Cyclical hourly pattern signals.
  | Weekday_sin, Weekday_cos | ✓ |  |  | Weekly periodicity.
  | Pkt Len Var |  |  | ✓ | Packet length variance for device anomaly detection.
  | Fwd/Bwd Pkt Len Std |  |  | ✓ | Directional payload dispersion.
  | Idle Max/Mean |  |  | ✓ | Idle durations per flow.
  | Active Min/Max |  |  | ✓ | Active burst durations.
  | Init Fwd/Bwd Win Byts |  |  | ✓ | Initial TCP window byte counts.
  | Fwd/Bwd Header Len |  |  | ✓ | Header length anomalies.
  | Pkt Size Avg |  |  | ✓ | Average packet size.
  | Fwd/Bwd Seg Size Avg |  |  | ✓ | Average TCP segment size.

- Attribute rationale captured in notebooks (feature correlation plots) and implied by lists above; no automated validation currently ensures consistent feature availability.

3. Model Layers
- Global layer: XGBoost model loaded via `joblib.load(GLOBAL_MODEL_PATH)` (`flask_detection/detection_utils.py:59-66`). `predict_proba` invoked on scaled feature matrix (`detection_utils.py:84-87`), producing attack probability; confidence uses maximum class probability.
- Edge layer: LSTM model loaded with TensorFlow `load_model(EDGE_MODEL_PATH)` (`detection_utils.py:67-74`). Edge feature matrix scaled, sequences constructed using sliding window length `SEQUENCE_LEN=5` (`detection_utils.py:96-108`). LSTM predictions produce two-class probabilities, with attack confidence computed as `1 - proba[:,0]`; leading timesteps padded with zeros to align array with original indices.
- Device layer: Keras MLP loaded via `load_model(DEVICE_MODEL_PATH)` (`detection_utils.py:75-81`). Input features scaled and fed to `.predict(batch_size=64)`, flattening results (`detection_utils.py:90-92`). Assumes model output is single-value probability per flow.
- Fusion: Weighted sum of confidences `fused = 0.3*g + 0.3*e + 0.4*d` followed by threshold `pred = (fused > 0.5)` (`detection_utils.py:112-117`). Fusion weights defined in `config.py:37-40`; threshold `THRESHOLD=0.5` in `config.py:41`.
- Output dictionary: generator yields per-index record containing `index`, `global_conf`, `edge_conf`, `device_conf`, `fused_score`, `predicted_label`, `true_label`, `original_label` (`detection_utils.py:123-134`).

4. Flask Detection Service
- File: `flask_detection/detection_server.py`.
- Flask app initialization (`detection_server.py:12-15`) enables CORS with credentials for origin `http://localhost:3000` using `flask_cors.CORS`.
- Endpoints:
  - `/status`: returns JSON `{"status":"Detection server running"}` (`detection_server.py:18-20`).
  - `/detect` (POST): logs start parameters, connects to MySQL using `MYSQL_CONFIG` from `config.py`. Immediately executes `TRUNCATE TABLE logs` (`detection_server.py:24-31`). Processes generator from `run_detection_pipeline()`; batches inserts using prepared statement `INSERT INTO logs (idx, global_conf, edge_conf, device_conf, fused_score, label_pred, label_true, original_label)`; commits per batch of `BATCH_INSERT_SIZE` (default 10,000). After each commit, sleeps `SLEEP_INTERVAL_SEC` seconds (default 0.1). Remaining records inserted after loop. On success returns JSON with `count` and `preview` of first 10 records. On exception, rolls back transaction but truncation already executed; logs traceback. Finally closes cursor and connection (`detection_server.py:22-72`).
  - `/api/core-detection` delegates to `/detect` for compatibility (`detection_server.py:74-76`).
- Debug configuration: module concludes with `if __name__ == "__main__": app.run(debug=True, host="0.0.0.0", port=5001)` exposing debugger publicly (`detection_server.py:78`).

5. Log Service Blueprint
- File: `flask_detection/detect_and_log.py`.
- Blueprint `detect_log_blueprint` registered under `/api/logs` in Flask app (`detection_server.py:16`).
- Endpoints (no authentication):
  - `/top10`: selects top fused scores limited to 10 (`detect_and_log.py:8-24`).
  - `/preview`: alias of `/top10` (`detect_and_log.py:36-38`).
  - `/all`: returns latest logs ordered by `detected_at` descending with optional `limit` parameter (`detect_and_log.py:40-63`).
  - `/summary`: aggregated counts for total attacks, DoS, DDoS using `original_label` string matches (`detect_and_log.py:65-91`).
  - `/anomalies`: returns all rows where `label_pred=1` ordered by `detected_at` descending (`detect_and_log.py:93-114`).
  - `/timeline`: groups anomalies by time bucket via `DATE_FORMAT(detected_at, '%H:%i:%s')` (`detect_and_log.py:117-146`).
  - `/top10_attacks`: counts attacks by `original_label` limited to 10 (`detect_and_log.py:148-169`).
  - `/filter`: accepts POST payload with filters (id, predicted/true labels, attack type, date range). Builds dynamic WHERE clause; note filter uses column `id` (column assumed to exist) whereas insertion uses `idx`—possible schema mismatch (`detect_and_log.py:171-239`).
- All endpoints open access; rely solely on DB connection per request with dictionary cursors.

6. Node/Express Gateway
- File: `src/app.js`.
- Responsibilities:
  - Loads environment variables via dotenv; verifies DB connection on startup (lines 29-55).
  - Configures Nodemailer transporter with SMTP settings stored in `.env` (lines 57-66).
  - Defines password validation regex and session middleware (lines 68-88).
  - Static assets served from `public/` directory; body parsing for JSON and URL-encoded forms.
  - Proxies: `/api/logs/all|filter|summary` proxied to Flask at `http://127.0.0.1:${FLASK_PORT}` with path rewrites (lines 90-113); `/api/core-detection` proxied to `/detect` with additional logging (lines 115-141).
  - Numerous authentication routes: login with optional MFA (lines 142-210), MFA verification/resend, forgot/reset password flow (lines 211-359), session-protected routes for dashboards and admin pages (lines 360-450+).
  - Admin API endpoints for user management (add, delete, edit) with bcrypt hashing (lines 452-520).
  - Additional diagnostics: `/test-db`, `/logs`, 404 handler (lines 521-573).
  - Server startup logs DB config (including plain password) and enumerates registered routes (lines 575-593), e.g., `console.log({ DB_HOST: ..., DB_PASS: ... })`.
- Sessions default to in-memory store; MFA implemented via email or TOTP; no CSRF tokens.

7. UI Layer
- `public/logs.js`: On DOMContentLoaded, fetches `http://localhost:5001/api/logs/all` with `credentials:'include'` (lines 1-70). Populates HTML table with log data; includes client-side CSV export. Because URL targets Flask directly, Express session enforcement is bypassed.
- `public/admin_dashboard.html`, `dashboard.html`, etc.: static pages styled via inline CSS/Bootstrap; rely on client-side scripts (where present) to query proxies. Dashboard logic not expanded here but no additional dynamic controls in admin dashboard file excerpt (cards, metrics placeholders).
- UI obtains data either directly from Flask or via Express proxies depending on page. No integrated build system; assets served verbatim.

8. Model & Artifact Inventory
- `Models/xgb_global_model.pkl`: joblib-serialized XGBoost binary model loaded by detection utilities.
- `Models/edge_layer_lstm_best.keras`: TensorFlow SavedModel/HDF5 LSTM network.
- `Models/device_layer_mlp_model.h5`: TensorFlow/Keras dense network for device layer.
- `XGBoost/xgboost_inads.json`, `.ubj`, `.model`: alternative serialized models; not referenced in code.
- No scaler artifacts (e.g., `StandardScaler` pickles) present; `save_scalers.py` intended to create them but fails due to missing config constants.
- Additional artifacts: `INADS_Data/Label_Encoder.pkl` for categorical encoding, but not directly used in runtime pipeline.

9. Database Schema & Behavior
- `flask_detection/detection_server.py` assumes MySQL database named `INADS` (`config.py:47-52`) with table `logs` containing columns: `idx`, `global_conf`, `edge_conf`, `device_conf`, `fused_score`, `label_pred`, `label_true`, `original_label`, `detected_at`. Schema file not included; inference based on insert statements and query usage in `detect_and_log.py`.
- Logs table truncated before each detection run (`detection_server.py:29`). If run fails mid-way, rollback prevents insertion but truncated data remains lost. No separate history table or run metadata.
- Additional table references: `anomalies` table used in Express `/api/logs/attacks` route (`src/app.js:150-168`) though not populated by detection service; assumed to exist with columns `original_label`, `label_pred`.
- MySQL connections established synchronously per request; no connection pooling. Credentials stored in `.env` but default fallback values hard-coded in config.

10. Known Issues Appendix
- Scaler leakage: `_prep_scaler_fit` refits scaler on inference data (`detection_utils.py:34-36`).
- Missing scaler paths: `save_scalers.py` imports undefined constants (`save_scalers.py:6-8`).
- Hard-coded paths/secrets: `config.py` defaults include absolute path and password; `src/app.js` logs secrets.
- Log truncation & unauthenticated `/detect`: `TRUNCATE` executed pre-insertion; no auth guard (`detection_server.py:22-36`).
- Frontend proxy bypass: `public/logs.js` fetches Flask directly (line 4).
- Model serialization fragility: joblib pickle load for XGBoost (`detection_utils.py:61`) despite JSON artifacts existing.
- Static fusion weights: `config.py:37-40`; no runtime override.
- Lack of run metadata/DB atomicity: No `run_id`, partial failures leave tables empty.
- Performance bottlenecks: Entire CSV loaded to memory (`detection_utils.py:49`); sleep per batch insert (`detection_server.py:53`) slows throughput.
- No seed/reproducibility controls: No `np.random.seed`, `tf.random.set_seed` in runtime code; metrics only printed.
- Flask debug mode & wide-open CORS: `app.run(debug=True, host="0.0.0.0")` and `supports_credentials=True` for all requests from specified origin.
- Manuscript divergence: `Research Paper/.../conference_101719.tex` describes autoencoder + XGBoost fusion not present in code.
- Additional: Blueprint `/filter` expects column `id` but insert uses `idx`; potential query mismatch (`detect_and_log.py:189-233`).
- Express logs sensitive data: `src/app.js:580` outputs DB credentials. Sessions stored in memory; may not scale but acceptable for current setup.

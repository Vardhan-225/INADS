0. Executive Overview
- Architecture: three-layer detection pipeline composed of Global layer (XGBoost classifier on flow-level volumetric/statistical features), Edge layer (TensorFlow LSTM operating on sequential windows), Device layer (TensorFlow/Keras MLP using behavioral/device-specific attributes), and a static weighted fusion block combining layer confidences (0.3/0.3/0.4) with a 0.5 threshold (`flask_detection/config.py:37-41`, `flask_detection/detection_utils.py:112-117`).
- Runtime stack: Flask detection service (`flask_detection/detection_server.py`) hosting inference endpoints; Node/Express application (`src/app.js`) handling authentication/MFA, static asset serving, and proxying to Flask; MySQL database accessed through `mysql.connector` for persistence; static UI under `public/` retrieving results. This document describes repository state as-is (commit workspace) without proposed changes.

1. Data & Provenance
- **Runtime dataset**: `INADS_Data/Data/Indexed_Dataset_Cyclical_Encoded.csv` (`flask_detection/config.py:6-14`). This CSV is the consolidated flow-level table generated during the Revised Approach notebooks and is the only file read in production.
- **Acquisition record**: `Research Paper/…/Dataset Exploration - CSE-CIC-IDS-2018.{docx,pdf}` lists every CSE-CIC-IDS-2018 source file (e.g., `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv`, `DoS_Attacks_Filtered.csv`), the attack categories covered, and confirms benign vs attack day coverage. These documents align with the staged CSVs stored under `INADS_Data/Data/` (e.g., `Benign_Traffic.csv`, `DoS_Attacks_Filtered.csv`, `Merged-Dataset-Final.csv`).
- **Preprocessing provenance**: Development notebooks located in `Notebooks/Revised Approach/` (`Dataset_Exploration.ipynb`, `Global_Layer.ipynb`, `Edge_Layer.ipynb`, `Device_Layer.ipynb`, `Core_Layer.ipynb`) describe cleansing, label normalization, timestamp conversion, and cyclical encoding. Section 1.x of `INADS - Implementation Documentation.{docx,pdf}` mirrors those steps, logging schema validation, duplicated flow removal, and index creation.
- **Schema expectations**: `run_detection_pipeline` slices the dataframe by feature lists in `flask_detection/config.py:17-34`, presuming all columns exist with numeric dtype (categorical values already mapped/encoded). There is no runtime dtype enforcement; pandas default coercion is relied upon. Feature order within models is consistent with the defined lists; notebooks document the same ordering.
- **Reference artefacts**: Supporting materials in `Research Paper/…/Images/` include correlation matrices, feature-importance graphics, and `Feature_Documentation.xlsx` that enumerate column definitions. `INADS_Data/Label_Encoder.pkl` stores encoders used during preprocessing but is not loaded in production code.

2. Feature Allocation
- Layer feature lists are declared in `flask_detection/config.py:17-34` and reflected in Section 2.x of `INADS - Implementation Documentation`. Correlation heatmaps and feature-importance plots under `Research Paper/…/Images/` back up the selection rationale.
- Layer-wise breakdown:
  - **Global**: 22 features (flow statistics, TCP flags, packet length extremes, throughput metrics, temporal cyclical encodings) tuned for volumetric anomalies.
  - **Edge**: 7 features (packet length extremes, directional packet rates, forward inter-arrival mean) organised for sequential LSTM modelling.
  - **Device**: 22 features capturing port behaviour, forward/reverse packet statistics, idle/active durations, TCP window/header characteristics, and temporal cyclicality.
- Feature table (✓ = feature used by layer model):

  | Feature | Global | Edge | Device | Description |
  | --- | --- | --- | --- | --- |
  | Flow Duration | ✓ |  | ✓ | Session length capturing volumetric anomalies and device dwell time.
  | Flow Byts/s | ✓ |  |  | Aggregate byte rate for volumetric detection.
  | Flow IAT Mean | ✓ |  | ✓ | Inter-arrival mean indicating traffic regularity across flows.
  | Flow IAT Std | ✓ |  | ✓ | Variability in packet timing.
  | Flow IAT Max | ✓ |  |  | Max gap to flag stealth/slow behaviors.
  | Dst Port | ✓ |  | ✓ | Encoded destination service information.
  | Protocol | ✓ |  |  | Transport protocol identifier.
  | SYN Flag Cnt | ✓ |  |  | TCP SYN flood indicator count.
  | ACK Flag Cnt | ✓ |  |  | Successful handshake acknowledgement frequency.
  | FIN Flag Cnt | ✓ |  |  | Termination pattern analyzer for reconnaissance.
  | PSH Flag Cnt | ✓ |  |  | Payload push anomaly detector.
  | Pkt Len Min | ✓ | ✓ |  | Minimum packet length per flow/window.
  | Pkt Len Max | ✓ | ✓ |  | Maximum packet length per flow/window.
  | Fwd Pkts/s | ✓ | ✓ |  | Forward packet rate.
  | Bwd Pkts/s | ✓ | ✓ |  | Reverse packet rate complement.
  | Fwd Pkt Len Max | ✓ | ✓ | ✓ | Peak forward payload size across layers.
  | Bwd Pkt Len Min | ✓ | ✓ | ✓ | Smallest reverse payload size.
  | TotLen Fwd Pkts | ✓ |  |  | Total forward bytes per flow.
  | TotLen Bwd Pkts | ✓ |  |  | Total reverse bytes per flow.
  | Hour_sin | ✓ |  | ✓ | Cyclical hour encoding (sine component).
  | Hour_cos | ✓ |  | ✓ | Cyclical hour encoding (cosine component).
  | Weekday_sin | ✓ |  |  | Weekly periodicity sine component.
  | Weekday_cos | ✓ |  |  | Weekly periodicity cosine component.
  | Fwd IAT Mean |  | ✓ |  | Forward inter-arrival mean inside sequence window.
  | Pkt Len Var |  |  | ✓ | Packet length variance per device flow.
  | Fwd Pkt Len Std |  |  | ✓ | Forward packet length standard deviation.
  | Bwd Pkt Len Std |  |  | ✓ | Reverse packet length standard deviation.
  | Idle Max |  |  | ✓ | Maximum idle time between packets.
  | Idle Mean |  |  | ✓ | Average idle interval.
  | Active Min |  |  | ✓ | Minimum active burst duration.
  | Active Max |  |  | ✓ | Maximum active burst duration.
  | Init Fwd Win Byts |  |  | ✓ | Initial forward TCP window bytes.
  | Init Bwd Win Byts |  |  | ✓ | Initial reverse TCP window bytes.
  | Fwd Header Len |  |  | ✓ | Forward header length aggregate.
  | Bwd Header Len |  |  | ✓ | Reverse header length aggregate.
  | Pkt Size Avg |  |  | ✓ | Mean packet size per device flow.
  | Fwd Seg Size Avg |  |  | ✓ | Average forward TCP segment size.
  | Bwd Seg Size Avg |  |  | ✓ | Average reverse TCP segment size.

- Attribute rationale is documented in `INADS - Implementation Documentation` §2.1–2.4 and by correlation/feature-importance artefacts in `Research Paper/…/Images/`. There is no automated schema validator—runtime simply indexes columns based on these lists.

3. Model Layers
- **Global (XGBoost)**: Loaded via `joblib.load(GLOBAL_MODEL_PATH)` (`flask_detection/detection_utils.py:59-66`); inference uses `predict_proba` on the scaler-transformed feature matrix (`detection_utils.py:84-87`) with the maximum class probability treated as confidence. Training artefacts live under `Research Paper/…/Final/Global/` (model pickle, results CSV, ROC curve, feature importance plot) and mirror the runtime asset.
- **Edge (LSTM)**: TensorFlow model loaded with `load_model(EDGE_MODEL_PATH)` (`detection_utils.py:67-74`). Edge features are scaled and converted into sliding windows of length `SEQUENCE_LEN=5` (`detection_utils.py:96-108`). Predictions yield `[benign, attack]` probabilities; attack confidence is computed as `1 - proba[:,0]` with leading timesteps padded to keep length alignment. Supporting artefacts are stored at `Final/Edge/LSTM/`.
- **Device (MLP)**: Keras dense network loaded via `load_model(DEVICE_MODEL_PATH)` (`detection_utils.py:75-81`). Scaled device features are passed to `.predict(batch_size=64)` (`detection_utils.py:90-92`), producing a single-column probability vector. `Final/Device/` includes the deployed MLP plus alternative autoencoder/transformer experiments with their confusion matrices and ROC curves.
- **Fusion**: Confidences are combined with static weights `W_GLOBAL=0.3`, `W_EDGE=0.3`, `W_DEVICE=0.4` (`config.py:37-40`) and thresholded at `THRESHOLD=0.5` to produce `predicted_label` (`detection_utils.py:112-117`). Additional fusion analyses (`core_layer_results_logistic_fusion.csv`, `…_neural_fusion.csv`, `…_adaptive.csv`) reside in `Final/Core/` but are not wired into runtime.
- **Output format**: `run_detection_pipeline` yields dictionaries containing `index`, per-layer confidences, fused score, predicted label, true label, and original string label (`detection_utils.py:123-134`). These records feed directly into the `/detect` insertion routine.

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
- **Runtime directory (`Models/`)**: Contains the exact artefacts consumed by `detection_utils.py`—`xgb_global_model.pkl`, `edge_layer_lstm_best.keras`, and `device_layer_mlp_model.h5`.
- **Alternative serialisations (`XGBoost/`)**: JSON/UBJ exports of the XGBoost model exist (`xgboost_inads.json`, `.ubj`, `.model`) but are not referenced in code; they can facilitate the planned migration away from pickle.
- **Final experiment repository**: `Research Paper/INADS___Intelligent_Network_Anomaly_Detection_System/Final/` stores evaluation-ready artefacts—per-layer result CSVs, confusion matrices, ROC curves, SHAP plot, comparative attack summaries, persisted scalers (`global_scaler.pkl`, `edge_scaler.pkl`, `device_scaler.pkl`), and fusion experiment outputs. These files document the empirical performance reported in the implementation docs.
- **Explainability & feature resources**: `Research Paper/…/Images/` holds correlation heatmaps, feature-importance plots, and `Feature_Documentation.xlsx`, all referenced in the narrative.
- **Label encoding**: `INADS_Data/Label_Encoder.pkl` remains from preprocessing workflows but is not imported during runtime inference.

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
- Fusion accuracy imbalance: `Research Paper/.../Final/layerwise_attack_detection_comparison.csv` shows the fused output severely under-detects infiltration attacks despite strong Global-layer performance, highlighting the need for adaptive weighting.
- Additional: Blueprint `/filter` expects column `id` but insert uses `idx`; potential query mismatch (`detect_and_log.py:189-233`).
- Express logs sensitive data: `src/app.js:580` outputs DB credentials. Sessions stored in memory; may not scale but acceptable for current setup.

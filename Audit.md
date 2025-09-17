0) Executive Summary  
INADS (Intelligent Network Anomaly Detection System) operationalizes a stratified intrusion-detection architecture in which a Flask-based inference layer, Node/Express perimeter, and MySQL persistence collaborate to evaluate CIC-IDS-2018 flow records. The system instantiates an XGBoost classifier (Global layer), a sequence-aware LSTM (Edge layer), and a Keras MLP (Device layer); their confidences are fused by a weighted sum before analytics endpoints and dashboards expose the results. Empirical correctness and operational trustworthiness are currently constrained by critical weaknesses: inference-time scaler re-fitting leaks ground-truth statistics, scaler artifacts are missing entirely, source paths and credentials are hard-coded, the detection API truncates history without authentication, and frontend scripts bypass the proxy and session layer.

Top findings (severity-ranked)
1. Detection pipeline refits `StandardScaler` on evaluation data (Critical) — induces label leakage and invalidates metrics.
2. Scaler persistence paths undefined (High) — `save_scalers.py` cannot run, preventing normalization governance.
3. Secrets/paths embedded in config and logs (High) — credentials exposed; deployment coupled to `/Users/athanneeru/...`.
4. `/detect` truncates logs and runs unauthenticated (High) — arbitrary callers can erase history and induce heavy jobs.
5. Frontend queries Flask directly (High) — sensitive telemetry bypasses Express session enforcement.

---

1) Repository Inventory  

Directory structure (≤3 levels)
- `flask_detection/` — Flask detection microservice
  - `config.py` — Global paths, feature schemas, DB credentials, fusion weights.
  - `detection_utils.py` — Data load, scaling, model inference, fusion.
  - `detection_server.py` — HTTP endpoints executing pipeline, batching MySQL inserts.
  - `detect_and_log.py` — REST blueprint exposing log summaries (`/top10`, `/summary`, `/filter`, etc.).
  - `save_scalers.py` — Intended scaler persistence (broken).
- `Models/` — Runtime artifacts (`xgb_global_model.pkl`, `edge_layer_lstm_best.keras`, `device_layer_mlp_model.h5`).
- `INADS_Data/` — Datasets, feature documentation, correlation figures.
  - `Data/Indexed_Dataset_Cyclical_Encoded.csv` — Primary inference dataset.
- `Notebooks/` — Jupyter notebooks (Old vs Revised Approach) detailing data prep and model training.
- `public/` — Static assets for dashboards (`admin_dashboard.html`, `logs.js`, etc.).
- `src/` — Express gateway (`app.js`) handling authentication, MFA, proxies.
- `Research Paper/INADS___Intelligent_Network_Anomaly_Detection_System/` — IEEE manuscript (`conference_101719.tex`), IEEEtran class, `fig1.png`.
- Root artifacts — `XGBoost/xgboost_inads.{json,ubj,model}`, virtualenv `INADS/`, `.env`, `requirements.txt`.

Key files and roles
- `flask_detection/config.py:6–52` — Declares filesystem defaults, feature lists per layer, weights, thresholds, MySQL credentials.
- `flask_detection/detection_utils.py:34–134` — Implements `_prep_scaler_fit`, `run_detection_pipeline` (load → scale → infer → fuse).
- `flask_detection/detection_server.py:12–78` — Flask app, CORS config, `/detect` workflow, DB batching.
- `flask_detection/detect_and_log.py:1–239` — Database read APIs returning JSON payloads.
- `src/app.js:31–593` — Express auth, session management, proxies to Flask, console logging.
- `public/logs.js:1–71` — Browser logic fetching and rendering detection logs (direct Flask call).
- `Research Paper/.../conference_101719.tex:1–140` — Manuscript describing architecture (divergent in places).

Model/weight inventory
- `Models/xgb_global_model.pkl` — joblib-serialized XGBoost classifier (binary).
- `Models/edge_layer_lstm_best.keras` — TensorFlow LSTM (Keras SavedModel/HDF5).
- `Models/device_layer_mlp_model.h5` — TensorFlow/Keras dense network.
- `XGBoost/xgboost_inads.{json,ubj}` — alternate serializations not currently wired into pipeline.
- No scaler artifacts present.

Datasets referenced
- `INADS_Data/Data/Indexed_Dataset_Cyclical_Encoded.csv` — default inference CSV.
- Supplementary CSVs (Benign_Traffic, DoS_Attacks_Filtered, etc.) used during model development.

---

2) Packet/Flow Lifecycle — What Happens Now  

1. **Ingestion** — `run_detection_pipeline` reads the full CSV into memory (`flask_detection/detection_utils.py:49`). Feature names (Flow Duration, TotLen, etc.) indicate flow-level units (CIC-IDS 2018). Null handling defers to pandas defaults.
2. **Label handling** — `Original_Label` duplicates `Label`; `Binary_Label` encodes benign as 0 and any other label as 1 (case-insensitive compare) (`lines 53–55`).
3. **Model loading** — `joblib.load` for XGBoost, `tensorflow.keras.models.load_model` for LSTM and MLP (`lines 59–81`).
4. **Scaling** — `_prep_scaler_fit` instantiates `StandardScaler` and calls `fit_transform` on detection data for each feature subset (`lines 84, 90, 96`). No persistence or schema enforcement.
5. **Edge sequences** — Rolling window (length = 5) constructs sequential tensors; first four rows padded with zero confidences (`lines 98–109`).
6. **Layer confidences** —
   - `c_g`: max probability from `xgbm.predict_proba` (`lines 84–87`).
   - `c_d`: flattened output from MLP `.predict` (`lines 90–92`).
   - `c_e`: `1 - edge_proba[:,0]` with leading zeros for alignment (`lines 101–108`).
7. **Fusion** — align arrays by minimum length; compute `S = 0.3*c_g + 0.3*c_e + 0.4*c_d`; threshold at 0.5 for predicted label (`lines 112–117`).
8. **Metrics** — accuracy and confusion matrix printed to stdout; no persistence (`lines 119–121`).
9. **Persistence** — `/detect` truncates `logs` table, batches inserts (`BATCH_INSERT_SIZE` = 10,000), commits, sleeps (`SLEEP_INTERVAL_SEC` = 0.1) (`flask_detection/detection_server.py:22–54`).
10. **UI exposure** — Express proxies `/api/logs/*`, but `public/logs.js` fetches `http://localhost:5001/api/logs/all` directly, bypassing session enforcement.

Assumptions/constraints
- Dataset must provide all configured feature columns with numeric encoding.
- Column order must match training; no schema validation.
- `logs` MySQL schema must contain columns referenced in inserts (`idx`, `global_conf`, `edge_conf`, `device_conf`, `fused_score`, `label_pred`, `label_true`, `original_label`, `detected_at`).
- Flow ordering assumed chronological to justify LSTM windows.
- Absolute paths assume macOS home directory unless overridden.

---

3) Attribute Dictionary  

| Feature | Layer(s) | Type | Function & Rationale | Source |
| --- | --- | --- | --- | --- |
| Flow Duration | Global, Device | Temporal | Distinguishes persistent benign sessions from short DoS floods; captures dwell time. | `config.py:18,30` |
| Flow Byts/s | Global | Rate | High throughput indicates volumetric DoS/DDoS events. | `config.py:18` |
| Flow IAT Mean | Global, Device | Temporal | Inter-arrival regularity; low mean reflects sustained flooding, high mean indicates stealth. | `config.py:18,30` |
| Flow IAT Std | Global, Device | Temporal | Dispersion of inter-arrival times; volatility signals crafted attacks. | `config.py:18,30` |
| Flow IAT Max | Global | Temporal | Long gaps reveal reconnaissance or throttled infiltration. | `config.py:18` |
| Dst Port | Global, Device | Protocol | Encoded service identifier; shifts highlight targeted services. | `config.py:19,29` |
| Protocol | Global | Protocol | Differentiates attack vectors by layer-4 protocol. | `config.py:19` |
| SYN Flag Cnt | Global | Behavioral | Elevated SYN counts flag SYN-flood. | `config.py:19` |
| ACK Flag Cnt | Global | Behavioral | Differentiates successful handshakes vs half-open floods. | `config.py:19` |
| FIN Flag Cnt | Global | Behavioral | Abnormal terminations indicating scanning. | `config.py:19` |
| PSH Flag Cnt | Global | Behavioral | Payload push irregularities reflect injection attempts. | `config.py:19` |
| Pkt Len Min/Max | Global, Edge | Volumetric | Detect payload anomalies; extremes reveal crafted packets. | `config.py:20,25` |
| Fwd/Bwd Pkts/s | Global, Edge | Rate | Directional rate imbalances common in floods. | `config.py:20,26` |
| Fwd Pkt Len Max | Global, Edge, Device | Volumetric | Highlights peak payload in forward direction. | `config.py:21,25,29` |
| Bwd Pkt Len Min | Global, Edge, Device | Volumetric | Detects minimal acknowledgement payloads or anomalies. | `config.py:21,25,29` |
| TotLen Fwd/Bwd Pkts | Global | Aggregated volume | Tracks total data per direction for volumetric anomalies. | `config.py:21` |
| Hour_sin/cos, Weekday_sin/cos | Global, Device | Temporal cyclical | Encode diurnal/weekly baselines; detect schedule deviations. | `config.py:22,34` |
| Pkt Len Var | Device | Statistical | Variation per flow indicates unusual payload dynamics. | `config.py:29` |
| Fwd/Bwd Pkt Len Std | Device | Statistical | Highlights dispersion differences at endpoint. | `config.py:30` |
| Idle Max/Mean | Device | Temporal | Device idle periods capture stealth infiltration. | `config.py:31` |
| Active Min/Max | Device | Temporal | Active burst signatures for attack behavior. | `config.py:31` |
| Init Fwd/Bwd Win Byts | Device | TCP handshake | Window size anomalies signal handshake tampering. | `config.py:32` |
| Fwd/Bwd Header Len | Device | Protocol overhead | Header length shifts indicate evasion techniques. | `config.py:33` |
| Pkt Size Avg | Device | Volumetric | Average payload size per flow differentiates infiltration. | `config.py:33` |
| Fwd/Bwd Seg Size Avg | Device | TCP segmentation | Segment size irregularities highlight exfiltration or tunneling. | `config.py:34` |

TODO: Cross-verify preprocessing provenance in `Notebooks/Revised Approach/*.ipynb` and document any additional transformations.

---

4) Findings  

#### 4.1 Scaler refit during detection — leakage risk (Critical)
- **Evidence**: `_prep_scaler_fit` instantiates `StandardScaler` and calls `fit_transform` within inference (`flask_detection/detection_utils.py:34–36, 84, 90, 96`).
- **Current behavior**: Detection run derives scaling parameters from evaluation data, then applies them to the same data.
- **Why it matters**: Ground-truth leakage inflates metrics; inconsistent normalization across runs; impossible to reproduce training-time conditions.
- **Remediation options**:
  1. Persist training scalers and load when `USE_PERSISTED_SCALERS=1` (recommended).
  2. Provide precomputed scaler statistics via config-managed artifacts.
- **Patch sketch**:
  ```python
  if os.getenv("USE_PERSISTED_SCALERS", "0") == "1":
      scaler = joblib.load(SCALER_GLOBAL_PATH)
      Xg = scaler.transform(df[GLOBAL_FEATURES])
  else:
      Xg, scaler = _prep_scaler_fit(df, GLOBAL_FEATURES)
  ```
- **Tests to add**: Unit test checking `.fit` not invoked when persisted scalers active; integration test ensuring repeated runs with same scaler yield identical outputs.
- **Residual risks**: Dataset drift still possible; schedule periodic scaler retraining and document dataset snapshots.

#### 4.2 Missing scaler paths in configuration (High)
- **Evidence**: `save_scalers.py` imports `SCALER_EDGE_PATH`, `SCALER_DEVICE_PATH` missing from `config.py` (`save_scalers.py:6–8`).
- **Current behavior**: Script fails to run; scalers not saved.
- **Why it matters**: Remediation in 4.1 blocked; normalization remains uncontrolled.
- **Options**:
  1. Define `SCALER_*_PATH` in config with env overrides (preferred).
  2. Refactor script to accept CLI arguments for output paths.
- **Patch sketch**:
  ```python
  SCALER_EDGE_PATH = os.getenv("SCALER_EDGE_PATH", os.path.join(BASE_DIR, "edge_scaler.pkl"))
  SCALER_DEVICE_PATH = os.getenv("SCALER_DEVICE_PATH", os.path.join(BASE_DIR, "device_scaler.pkl"))
  ```
- **Tests**: Execute script expecting artifact files; static analysis verifying config exports exist.
- **Residual risks**: Overwrite of scalers—mitigate via versioned filenames (e.g., timestamped).

#### 4.3 Hard-coded paths and plaintext secrets (High)
- **Evidence**: `MODEL_BASE_DIR` default `/Users/athanneeru/...` (`config.py:6`); `MYSQL_PASSWORD` default `Catsanddogs#666` (`config.py:51`, `.env:3`); Express logs emit DB config (`src/app.js:580`) and request headers including credentials (`src/app.js:131`).
- **Current behavior**: Deployment coupled to one workstation path; secrets exposed in repo and logs.
- **Why it matters**: Security risk, lack of portability, credentials leakage.
- **Options**:
  1. Require environment variables for secrets; fail fast when absent; redact logs (recommended).
  2. Implement centralized config loader that validates environment-specific inputs.
- **Patch sketch**:
  ```python
  def require_env(key):
      value = os.getenv(key)
      if not value:
          raise RuntimeError(f"{key} is required")
      return value

  MYSQL_CONFIG = {
      "host": require_env("MYSQL_HOST"),
      "user": require_env("MYSQL_USER"),
      "password": require_env("MYSQL_PASSWORD"),
      "database": require_env("MYSQL_DB"),
  }
  ```
  In Express, gate logging with `LOG_SENSITIVE_CONFIG` flag and redact secrets.
- **Tests**: Startup should abort without secrets; logs verified to exclude sensitive data.
- **Residual risks**: `.env` still stores secrets—mitigate with `.env.example` and documented secret-management procedures.

#### 4.4 `/detect` truncates logs and is unauthenticated (High)
- **Evidence**: `cursor.execute("TRUNCATE TABLE logs")` without auth guard (`flask_detection/detection_server.py:22–36`).
- **Current behavior**: Any POST wipes history before new run; no authentication or rate limiting.
- **Why it matters**: Enables data loss, denial-of-service, absence of auditability.
- **Options**:
  1. Add API key/session validation and run-scoped deletions (recommended).
  2. Move compute to authenticated async worker with run metadata.
- **Patch sketch**:
  ```python
  if os.getenv("REQUIRE_API_KEY", "0") == "1":
      if request.headers.get("X-INADS-KEY") != os.getenv("INADS_API_KEY"):
          return jsonify({"error": "Unauthorized"}), 401

  if os.getenv("PRESERVE_HISTORY", "1") == "1":
      cursor.execute("DELETE FROM logs WHERE run_id = %s", (run_id,))
  else:
      cursor.execute("TRUNCATE TABLE logs")
  ```
- **Tests**: Ensure unauthorized request blocked; run history retained when preserving.
- **Residual risks**: Table growth—use `runs` metadata and retention policy.

#### 4.5 Frontend bypasses proxy/session (High)
- **Evidence**: `public/logs.js` fetches Flask directly (`http://localhost:5001/api/logs/all`) while Express proxies exist (`src/app.js:92–113`).
- **Current behavior**: Browser bypasses Express session controls; Flask endpoints unauthenticated.
- **Why it matters**: Exposes sensitive telemetry outside intended auth mechanisms.
- **Options**:
  1. Switch frontend to `/api/logs/all` (relative path) and optionally enforce auth in Flask blueprint (preferred).
  2. Restrict Flask network exposure (bind to localhost only).
- **Patch sketch**:
  ```javascript
  const baseUrl = window.location.origin;
  fetch(`${baseUrl}/api/logs/all`, { credentials: 'include' })
  ```
- **Tests**: UI integration verifying login required; direct Flask call should fail.
- **Residual risks**: Reverse proxy misconfig—mitigate with firewall/ACL.

#### 4.6 Model serialization fragility (Medium)
- **Evidence**: Global model loaded from `.pkl` (`detection_utils.py:61`); JSON/UBJ alternatives unused.
- **Current behavior**: Pickle requires identical library versions; potential code execution if tampered.
- **Why it matters**: Reproducibility limited; security risk from untrusted pickle.
- **Options**:
  1. Migrate to XGBoost JSON/UBJ using `Booster.load_model` (recommended).
  2. Validate pickle metadata before load.
- **Patch sketch**:
  ```python
  if GLOBAL_MODEL_PATH.endswith('.json'):
      booster = xgb.Booster()
      booster.load_model(GLOBAL_MODEL_PATH)
      xgbm = xgb.XGBClassifier()
      xgbm._Booster = booster
  else:
      warnings.warn('Loading pickle model; ensure trusted environment.')
  ```
- **Tests**: Regression ensuring predictions unchanged after migration; negative test for version mismatch.
- **Residual risks**: JSON size; maintain artifact registry.

#### 4.7 Fusion weights rigid and unchecked (Medium)
- **Evidence**: `W_GLOBAL`, `W_EDGE`, `W_DEVICE`, `THRESHOLD` constants (`config.py:38–41`). No validation or dynamic control.
- **Current behavior**: Weighted sum static; cannot disable layers or run ablations without code edits.
- **Why it matters**: Research iteration hindered; misconfiguration risk.
- **Options**:
  1. Load weights from JSON env var with sum validation; introduce layer toggles (recommended).
  2. Use external config file describing fusion strategy.
- **Patch sketch**:
  ```python
  FUSE_WEIGHTS = json.loads(os.getenv('FUSE_WEIGHTS', '{"global":0.3,"edge":0.3,"device":0.4}'))
  assert abs(sum(FUSE_WEIGHTS.values()) - 1.0) < 1e-6
  ENABLE_GLOBAL = os.getenv('ENABLE_GLOBAL', '1') == '1'
  ```
- **Tests**: Unit test verifying weight normalization; ablation test confirming disabled layer contributions zeroed.
- **Residual risks**: JSON misconfiguration; mitigate via logging.

#### 4.8 Database insert integrity (Medium)
- **Evidence**: Manual batching with `executemany`, `time.sleep`, `TRUNCATE` executed pre-transaction (`detection_server.py:22–58`).
- **Current behavior**: On failure, rollback occurs but truncated data already lost; no run metadata.
- **Why it matters**: Data integrity risk, no audit trail, limited observability.
- **Options**:
  1. Add `runs` table and `run_id` column; wrap operations in run-specific transactions (recommended).
  2. Use MySQL bulk load or stored procedure with transactional semantics.
- **Patch sketch**:
  ```python
  cursor.execute("INSERT INTO runs (status) VALUES ('running')")
  run_id = cursor.lastrowid
  buf.append((run_id, rec['index'], ...))
  cursor.executemany("INSERT INTO logs (run_id, idx, ...) VALUES (%s,%s,...)", buf)
  ```
- **Tests**: Simulate failure mid-run; ensure prior run data persists.
- **Residual risks**: Table growth—apply retention strategies.

#### 4.9 Performance/memory constraints (Medium)
- **Evidence**: Whole CSV loaded, LSTM sequences materialized, `time.sleep` after commits (`detection_utils.py`, `detection_server.py:53`).
- **Current behavior**: High memory footprint; artificial delay; no streaming.
- **Why it matters**: Limits scalability; unrealistic for near-real-time detection.
- **Options**:
  1. Stream chunks with sliding window state for LSTM (preferred).
  2. Parameterize and possibly disable `SLEEP_INTERVAL_SEC` in production.
- **Patch sketch**:
  ```python
  chunk_size = int(os.getenv('CHUNK_SIZE', '0'))
  if chunk_size:
      for chunk in pd.read_csv(DATA_PATH, chunksize=chunk_size):
          process_chunk(chunk)
  else:
      df = pd.read_csv(DATA_PATH)
  ```
- **Tests**: Benchmark throughput and memory usage with `CHUNK_SIZE` enabled.
- **Residual risks**: Maintaining LSTM window context across chunks—document approach.

#### 4.10 Reproducibility deficits (Medium)
- **Evidence**: No deterministic seeds; metrics only printed; artifacts not stored.
- **Current behavior**: Retraining and detection runs non-deterministic; metrics not traceable.
- **Why it matters**: Weak reproducibility undermines academic credibility.
- **Options**:
  1. Introduce `INADS_SEED` and set seeds for `numpy`, `tensorflow`, `random`; persist metrics (recommended).
  2. Create manifest capturing model versions, dataset hashes.
- **Patch sketch**:
  ```python
  SEED = int(os.getenv('INADS_SEED', '42'))
  np.random.seed(SEED)
  tf.random.set_seed(SEED)
  random.seed(SEED)
  ```
  Persist metrics to `{run_id}_metrics.json`.
- **Tests**: Repeated runs produce identical metrics; hashed outputs match.
- **Residual risks**: GPU nondeterminism; document limitations.

#### 4.11 UI/Proxy misalignment (Medium)
- **Evidence**: Express proxies defined (`src/app.js:92–140`) but frontend bypasses them.
- **Current behavior**: Node-level logging and error handling unused; clients depend on Flask port visibility.
- **Why it matters**: Operational complexity, inconsistent security boundary.
- **Options**:
  1. Align frontend to proxy routes (recommended).
  2. Remove proxies and enforce auth at Flask level (less ideal).
- **Patch sketch**: adjust JS to use relative routes (see 4.5) and ensure Node handles responses.
- **Tests**: Verify Node logs show proxied requests; ensure direct Flask call fails when blocked.
- **Residual risks**: None once proxies enforced; monitor for CORS issues.

#### 4.12 Manuscript divergence from implementation (Medium)
- **Evidence**: Paper describes Device layer "Isolation Forest + MLP" and XGBoost fusion meta-model (`conference_101719.tex:83–110`), not reflected in code.
- **Current behavior**: Documentation misrepresents actual system.
- **Why it matters**: Academic integrity; reviewer scrutiny.
- **Options**:
  1. Update manuscript to reflect code (preferred).
  2. Reintroduce autoencoder and XGBoost fusion into code (large effort).
- **Plan**: Revise sections on Device layer and Fusion, reposition deprecated components as future work.
- **Residual risks**: Future divergence; maintain changelog linking code commits to manuscript revisions.

#### 4.13 Flask debug mode and permissive diagnostics (Medium)
- **Evidence**: `app.run(debug=True, host="0.0.0.0", port=5001)` enables debugger on externally exposed interface (`flask_detection/detection_server.py:78`); `CORS(app, supports_credentials=True, origins=["http://localhost:3000"])` allows credentialed cross-origin requests (`flask_detection/detection_server.py:15`).
- **Current behavior**: The Flask server advertises Werkzeug debugger and reloader to remote clients and accepts credential-bearing requests from any browser served from the configured origin, even when the Express gateway should front the service.
- **Why it matters**: Debug mode can leak stack traces and enable remote code execution via the debugger PIN; coupled with credentialed CORS, it widens the attack surface if Flask is ever exposed beyond localhost.
- **Options**:
  1. Disable debug/reloader in production by guarding with `if __name__ == "__main__" and os.getenv("FLASK_DEBUG", "0") == "1"` (recommended for research deployments).
  2. Limit Flask binding to loopback (`127.0.0.1`) and rely on the Node proxy; optionally tighten CORS origins via environment variable.
- **Patch sketch**:
  ```python
  debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
  bind_host = os.getenv("FLASK_BIND_HOST", "127.0.0.1")
  allowed_origins = os.getenv("FLASK_CORS_ORIGINS", "http://localhost:3000").split(",")
  CORS(app, supports_credentials=True, origins=allowed_origins)

  if __name__ == "__main__":
      app.run(debug=debug_mode, host=bind_host, port=int(os.getenv("FLASK_PORT", 5001)))
  ```
- **Tests**: Start server with default settings and verify debugger disabled; set `FLASK_DEBUG=1` in development to ensure opt-in works; integration test confirming CORS origins configurable.
- **Residual risks**: Misconfiguration may still expose service; mitigate with deployment documentation and reverse-proxy enforcement.

---

5) Measurement & Evidence Plan  

Latency/Throughput
- Instrument `time.perf_counter()` around CSV load, each scaler transform, every model inference, fusion, and batch insert.
- Log structured telemetry every `TELEMETRY_INTERVAL` rows (default 10,000) capturing stage, duration, cumulative rows, throughput.

Memory/CPU
- Use `psutil.Process(os.getpid())` to sample `memory_info().rss` and `cpu_percent` before/after major stages.
- Emit resource metrics alongside latency telemetry for correlation.

Output artifacts
- `{run_id}_metrics.json`: `{run_id, timestamp, rows, accuracy, confusion_matrix, fuse_weights, threshold, seed, dataset_hash}`.
- `{run_id}_telemetry.csv`: `stage,batch_index,rows_processed,duration_ms,throughput_rows_per_s,rss_mb,cpu_percent`.

Ablation hooks
- Config toggles `ENABLE_GLOBAL`, `ENABLE_EDGE`, `ENABLE_DEVICE`.
- `FUSE_STRATEGY` parameter to compare weighted vs alternative fusion (e.g., majority vote).
- Telemetry should record active layers and strategy for each run.

---

6) Proposed Non-Destructive Patch Plan  

Configuration additions (defaults preserve current behavior)
- `USE_PERSISTED_SCALERS=0`
- `SCALER_GLOBAL_PATH`, `SCALER_EDGE_PATH`, `SCALER_DEVICE_PATH` defaulting to `<BASE_DIR>/<layer>_scaler.pkl`
- `INADS_SEED=42`
- `CHUNK_SIZE=0` (0 = full load)
- `FUSE_WEIGHTS='{"global":0.3,"edge":0.3,"device":0.4}'`
- `FUSE_THRESHOLD=0.5`
- `ENABLE_GLOBAL=1`, `ENABLE_EDGE=1`, `ENABLE_DEVICE=1`
- `REQUIRE_API_KEY=0`, `INADS_API_KEY=` (empty)
- `PRESERVE_HISTORY=1`
- `LOG_SENSITIVE_CONFIG=0`
- `TELEMETRY_INTERVAL=10000`
- `ENFORCE_SESSION=0`

Database schema sketch
```
CREATE TABLE runs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  status ENUM('running','success','failed') NOT NULL,
  notes TEXT NULL
);

ALTER TABLE logs
  ADD COLUMN run_id BIGINT NOT NULL,
  ADD INDEX idx_logs_run_id (run_id),
  ADD CONSTRAINT fk_logs_runs FOREIGN KEY (run_id) REFERENCES runs(id);
```

API extensions (backward-compatible)
- `POST /detect_async` — validates API key, enqueues detection, returns `run_id`.
- `GET /status/<run_id>` — returns run metadata (counts, status, timestamps).
- `GET /metrics/<run_id>` — serves metrics JSON artifact.
- `GET /telemetry/<run_id>` — streams telemetry CSV.
- Existing `/detect` remains but logs deprecation warning; defaults to synchronous path for compatibility.

Telemetry logging
- Emit JSON logs per stage with `stage`, `batch_index`, `rows_processed`, `duration_ms`, `rss_mb`, `cpu_percent`, `weights`, `threshold`, `seed`, `flags`.

---

7) Validation Checklist  

Correctness
- Confirm persisted scalers loaded (when enabled) and `.fit` unsued; log message verifying scaler paths.
- Inject malformed dataset to ensure schema validator raises descriptive error.
- Compare predictions across repeated runs with identical scalers to confirm determinism.

Security
- Review logs to ensure secrets redacted when `LOG_SENSITIVE_CONFIG=0`.
- Attempt `/detect` without API key to confirm 401; with key to confirm success.
- Access Flask endpoints directly when `ENFORCE_SESSION=1` to verify denial.

Reproducibility
- Set `INADS_SEED`, rerun detection, confirm identical metrics and telemetry; store artifact hashes.
- Document reproducible workflow for regenerating figures from notebooks.

Performance
- Inspect telemetry for latency and throughput metrics; ensure `SLEEP_INTERVAL_SEC` obeyed.
- Verify memory usage within acceptable bounds when `CHUNK_SIZE` specified.

UI
- Confirm frontend uses `/api/logs/*`; Node proxy logs demonstrate routing.
- Validate CORS origins restricted to intended production domain.
- Ensure MFA/session flows unaffected by telemetry instrumentation.

---

8) Appendix  

Config matrix

| Key | Default | Location |
| --- | --- | --- |
| `MODEL_BASE_DIR` | `/Users/athanneeru/Documents/GitHub/INADS/Models` | `config.py:6` |
| `DATA_PATH` | `/Users/.../Indexed_Dataset_Cyclical_Encoded.csv` | `config.py:7` |
| `GLOBAL_MODEL_PATH` | `<BASE_DIR>/xgb_global_model.pkl` | `config.py:9` |
| `EDGE_MODEL_PATH` | `<BASE_DIR>/edge_layer_lstm_best.keras` | `config.py:10` |
| `DEVICE_MODEL_PATH` | `<BASE_DIR>/device_layer_mlp_model.h5` | `config.py:11` |
| `OUTPUT_CSV` | `<BASE_DIR>/core_layer_results.csv` | `config.py:13` |
| `W_GLOBAL/W_EDGE/W_DEVICE` | `0.3/0.3/0.4` | `config.py:38–40` |
| `THRESHOLD` | `0.5` | `config.py:41` |
| `BATCH_SIZE` | `10000` | `config.py:44` |
| `SLEEP_SEC` | `0.1` | `config.py:45` |
| `MYSQL_HOST` | `localhost` | `config.py:49` |
| `MYSQL_USER` | `root` | `config.py:50` |
| `MYSQL_PASSWORD` | `Catsanddogs#666` | `config.py:51` |
| `MYSQL_DB` | `INADS` | `config.py:52` |
| `.env` keys | `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `SESSION_SECRET`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `FLASK_PORT` | `.env:1–11` |
| Flask CORS origins | `['http://localhost:3000']` | `detection_server.py:15` |
| Express proxy target | `http://127.0.0.1:${FLASK_PORT}` | `src/app.js:92` |

Traceability (code → manuscript updates)

| Implementation element | Manuscript section requiring update |
| --- | --- |
| Weighted fusion (`detection_utils.py:115`) | Revise Core Fusion section to describe weighted average rather than XGBoost meta-classifier. |
| Device layer (MLP only) | Update Device layer subsection; reposition autoencoder narrative as prior iteration/future work. |
| Future work topics (blockchain, federated learning) | Clarify these as aspirational and not implemented. |
| Metrics generation | Align evaluation section with actual metrics (accuracy, confusion matrix) or extend pipeline accordingly. |
| Log truncation & history | Document current limitation and planned remediation. |

Potential pitfalls
- Missing/extra columns or wrong dtypes in CSV → KeyError/ValueError during scaling.
- Column order drift breaks scaler assumptions.
- Dataset shorter than 5 rows yields zeroed edge confidences.
- Class imbalance not addressed; 0.5 threshold may be suboptimal.
- MySQL schema not version-controlled; environment drift risk.
- Truncation combined with rollback still results in data loss on failure.
- Secrets embedded in repo and `.env` risk exposure.
- XGBoost pickle compatibility across environments uncertain.
- Express session store defaults to in-memory; not production-grade.

References
- `flask_detection/config.py:6–52` — configuration definitions.
- `flask_detection/detection_utils.py:34–134` — scaler usage, inference, fusion.
- `flask_detection/detection_server.py:22–72` — `/detect` truncation and batch insertion.
- `flask_detection/detect_and_log.py:1–239` — log endpoints and queries.
- `flask_detection/save_scalers.py:6–24` — missing scaler path constants.
- `src/app.js:31–593` — Express server, proxy config, credential logging.
- `public/logs.js:1–71` — direct Flask fetch behavior.
- `Research Paper/INADS___Intelligent_Network_Anomaly_Detection_System/conference_101719.tex:83–140` — manuscript architecture description.
- `.env:1–11` — environment variables storing secrets.
- `requirements.txt:1–48` — dependency pinning (TensorFlow 2.16, XGBoost 3.0.5, etc.).
- `INADS_Data/Data/Indexed_Dataset_Cyclical_Encoded.csv` — primary dataset path.

Unknowns / follow-ups
- MySQL schema details for `logs` and `anomalies` (confirm via DB introspection).
- Preprocessing specifics in notebooks (identify exact transformations and cell references).
- Training procedure metadata (seeds, hyperparameters) to align with reproducibility plan.
- Session storage strategy in Express (defaults to in-memory; evaluate for production suitability).

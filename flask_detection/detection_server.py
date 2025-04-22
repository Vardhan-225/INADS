from flask import Flask, jsonify
from flask_cors import CORS
from detection_utils import run_detection_pipeline
from config import MYSQL_CONFIG
import mysql.connector
import os

from flask_detection.detect_and_log import detect_log_blueprint

app = Flask(__name__)
CORS(app)

@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "Detection server is running."})

@app.route("/detect")
def detect():
    print("➡️ /detect endpoint triggered")
    try:
        output = run_detection_pipeline()
        print("✔️ Pipeline executed, result count:", len(output))
        if not isinstance(output, list) or not isinstance(output[0], dict):
            print("⚠️ Unexpected result structure from pipeline")
            raise ValueError("run_detection_pipeline() must return a list of dictionaries.")

        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()

        # Clear old logs
        cursor.execute("TRUNCATE TABLE logs")

        # Insert new detection results
        insert_query = """
            INSERT INTO logs 
              (idx, global_conf, edge_conf, device_conf, fused_score, label_pred, label_true, original_label)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        for r in output:
            cursor.execute(insert_query, (
                r["index"],
                r["global_conf"],
                r["edge_conf"],
                r["device_conf"],
                r["fused_score"],
                r["predicted_label"],
                r["true_label"],
                r.get("original_label", "Unknown")
            ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify(output[:10])
    except Exception as e:
        import traceback
        print("❌ DETECTION SERVER ERROR:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Mount logs blueprint
app.register_blueprint(detect_log_blueprint, url_prefix="/api/logs")

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=5001)
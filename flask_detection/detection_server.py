from flask import Flask, request, jsonify
from flask_cors import CORS
from detection_utils import run_detection_pipeline
from config import MYSQL_CONFIG
import mysql.connector
import os

app = Flask(__name__)
CORS(app)

# Set up MySQL connection (basic example)
db_conn = mysql.connector.connect(
    host=MYSQL_CONFIG["host"],
    user=MYSQL_CONFIG["user"],
    password=MYSQL_CONFIG["password"],
    database=MYSQL_CONFIG["database"]
)

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

        results = output

        # Persist current run into anomalies table
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        # Clear old logs
        cursor.execute("TRUNCATE TABLE anomalies")
        # Insert new results
        insert_query = """
            INSERT INTO anomalies 
              (idx, global_conf, edge_conf, device_conf, fused_score, label_pred, label_true)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        for r in results:
            cursor.execute(insert_query, (
                r["index"],
                r["global_conf"],
                r["edge_conf"],
                r["device_conf"],
                r["fused_score"],
                r["predicted_label"],
                r["true_label"]
            ))
        conn.commit()
        cursor.close()
        conn.close()

        print(f"✅ Returning {len(results[:10])} results after DB update")
        return jsonify(results[:10])  # Return first 10
    except Exception as e:
        import traceback
        print("❌ DETECTION SERVER ERROR:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=port)
from flask import Flask, request, jsonify
import requests
import time
import psycopg2
import os
from flask_cors import CORS, cross_origin
import traceback
import json

app = Flask(__name__)
CORS(app)

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"),
    database=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    port=5432
)
cur = conn.cursor()

class ByteEncoder(json.JSONEncoder):
    def deafult(self,obj):
        if isinstance(obj,bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.deafult(self,obj)

@app.route('/', methods=['GET'])
def main():
    menu = {
        "Get agent frames": "/agents/get_frames",
        "Get frame": "/frames/<frame_id>",
        "Add frames": "/add/frames"
    }
    return menu

@app.route('/agents/get_frames', methods=['POST'])
def list_frames():
    try:
        content = request.get_json()
        agent_id = content["AgentID"]
        timestamp_start = content["TimestampStart"]
        timestamp_end = content["TimestampEnd"]


        cur.execute("SELECT * FROM agents WHERE agent_id = (%s);", [int(agent_id)])
        resp = {
            "AgentID": agent_id,
            "Frames": []
        }
        cur.execute("SELECT * FROM frames WHERE agent_id = (%s) AND frame_timestamp BETWEEN (%s) AND (%s);", [int(agent_id),timestamp_start,timestamp_end])
        results = cur.fetchall()
        for result in results:
            frame = {
                "FrameID": result[0],
                "FrameInfo": result[2],
                "FrameTimestamp": result[3],
                "FrameAdditionalData": result[4],
                "FrameLabel": result[5]
            }
            resp["Frames"].append(frame)

    except Exception:
        resp = {"error": f"There is no agent with AgentID = {agent_id}"}

    return resp


@app.route('/frames/<frame_id>', methods=['GET'])
def get_measure_info(frame_id):
    try:
        frame_id = int(frame_id)
        cur.execute("SELECT * FROM Frames WHERE frame_id = (%s);", [int(frame_id)])
        result = cur.fetchone()
        resp = {
                "FrameID": result[0],
                "FrameAgent": result[1],
                "FrameInfo": result[2],
                "FrameTimestamp": result[3],
                "FrameAdditionalData": result[4],
                "FrameLabel": result[5]
        }

    except Exception:
        resp = {"error": f"There is no frame with FrameID = {frame_id}"}

    return resp

@app.route("/add/frames", methods=['POST'])
def add_measure():
    try:
        content = request.get_json()
        agent_id = content["AgentID"]
        frames = content["Frames"]
        print(len(frames))
        counter = 0
        for frame in frames:
            f_info = frame["FrameInfo"]
            f_timestamp = frame["Timestamp"]
            f_additional_data = frame["AdditionalData"]
            f_label = frame["Label"]
            sql = """
                    INSERT INTO frames (agent_id, frame_info, frame_timestamp, frame_additional_data, frame_label)
                    VALUES (%s, %s, %s, %s, %s) RETURNING frame_id;
                    """
            cur.execute(sql, (int(agent_id), json.dumps(f_info, cls=ByteEncoder), f_timestamp, json.dumps(f_additional_data, cls=ByteEncoder), f_label))
            frame_id = cur.fetchone()[0]
            conn.commit()
            if frame_id:
                counter = counter + 1 
        resp = {"result": "Success", "Frames added:": counter}

    except Exception as e:
        print(e)
        print(traceback.print_exc())
        resp = {"result": "Failed"}


    return resp


# EVERY OTHER REQUEST
@app.errorhandler(404)
def handle_404(e):
    return {"error": "Not Found"}
#app.run(port=5000)
import base64
import os
import re
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.TAXII import TAXII
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
from lib.api.Intezer import Intezer
from lib.Filter import Filter
from lib.Database import Database
import jwt

load_dotenv()

app = Flask(__name__)
db_manager = Database(database_name='mydatabase')


def check_header():
    public_key = os.environ.get("SECRET_KEY")
    auth_header = request.headers.get('Authorization')

    if auth_header is None:
        return jsonify({"error": "Authorization header is missing"}), 401

    try:
        _, token = auth_header.split()
        decoded_payload = jwt.decode(token, public_key, algorithms=["HS256"])

        if "username" in decoded_payload and decoded_payload["username"] == "herma":
            return {"ok"}
        else:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"Token has expired."})
    except jwt.InvalidTokenError:
        return jsonify({"Invalid token."})
    except ValueError:
        return jsonify({"error": "Invalid Authorization header format"}), 401


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    authorized = check_header()
    if "ok" in authorized:
        return render_template('index.html')
    else:
        return authorized



@app.route('/api/scan/latest', methods=['GET'])
def get_latest_scan():
    authorized = check_header()
    if "ok" in authorized:
        filter = Filter()
        return filter.get_last_scans()
    else:
        return authorized


def is_sha256(hash_string):
    # Check if the string matches the SHA256 pattern
    return re.match(r'^[a-fA-F0-9]{64}$', hash_string) is not None


@app.route('/api/scan/<hash>', methods=['GET'])
def scan_api(hash):
    authorized = check_header()
    if "ok" in authorized:
        # Check if the provided hash is a valid SHA256 hash
        if not is_sha256(hash):
            error_response = {
                "error": "hash_error",
                "desc": "algorithm is not sha256"
            }
            return jsonify(error_response), 400  # Return a 400 Bad Request status

        filter = Filter()
        return filter.get_hash_data(hash)
    else:
        return authorized



@app.route('/api/file/upload/', methods=["POST"], strict_slashes=False)
def search_by_file():
    authorized = check_header()
    if "ok" in authorized:
        # Save File
        if 'file' not in request.files:
            return jsonify({"status": "no_file"})

        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "no_file"})

        filename = os.path.join(os.environ.get("UPLOAD_FOLDER"), file.filename)
        file.save(filename)

        file_analysis = FileAnalysis()
        result = file_analysis.get_uploaded_fileinfo(filename)

        filter = Filter()
        return filter.get_hash_data(result["sha256"])
    else:
        return authorized


@app.route('/api/file/virustotal/', methods=["POST"])
def virustotal():
    authorized = check_header()
    if "ok" in authorized:

        api_key = os.environ.get("VIRUSTOTAL_API_TOKEN")
        file_sha256 = request.form.get('hash')
        virustotal = Virustotal(api_key)

        if file_sha256 is not None and file_sha256 != '':
            data = virustotal.get_desired_data(file_sha256)
        else:
            data = {"error": "No parameters"}

        return data
    else:
        return authorized


@app.route('/api/file/hybrid/', methods=["POST"])
def hybrid():
    authorized = check_header()
    if "ok" in authorized:
        api_key = os.environ.get("HYBRID_API_TOKEN")
        file_sha256 = request.form.get('hash')
        hybrid = Hybrid(api_key)

        if file_sha256 is not None and file_sha256 != '':
            data = hybrid.get_desired_data(file_sha256)
        else:
            data = {"error": "No parameters"}

        return jsonify(data)
    else:
        return authorized


@app.route('/api/file/otx/', methods=["POST"])
def otx():
    authorized = check_header()
    if "ok" in authorized:
        api_key = os.environ.get("OTX_API_TOKEN")
        file_sha256 = request.form.get('hash')
        otx = OTX(api_key)

        if file_sha256 is not None and file_sha256 != '':
            data = otx.get_desired_data(file_sha256)
        else:
            data = {"error": "No parameters"}

        return jsonify(data)
    else:
        return authorized


@app.route('/api/file/intezer/', methods=["POST"])
def intezer():
    authorized = check_header()
    if "ok" in authorized:
        api_key = os.environ.get("Intezer_TOKEN")
        file_sha256 = request.form.get('hash')
        intezer = Intezer(api_key)

        if file_sha256 is not None and file_sha256 != '':
            data = intezer.get_desired_data(file_sha256)
        else:
            data = {"error": "No parameters"}

        return jsonify(data)
    else:
        return authorized


@app.route('/api/charts/numberofscans', methods=["GET"])
def linechart():
    authorized = check_header()
    if "ok" in authorized:

        filter = Filter()
        data = filter.get_every_scan_per_day()
        return jsonify(data)
    else:
        return authorized

@app.route('/api/charts/usedindicators', methods=["GET"])
def barchart():
    authorized = check_header()
    if "ok" in authorized:

        filter = Filter()
        data = filter.get_last_attack_indicators()
        return jsonify(data)
    else:
        return authorized


@app.route('/api/charts/mostusedttps', methods=["GET"])
def piechart():
    authorized = check_header()
    if "ok" in authorized:

        filter = Filter()
        data = filter.get_last_most_ttps()
        return jsonify(data)
    else:
        return authorized

@app.route('/taxii2/', methods=['GET'])
def taxii_discovery():
    authorized = check_header()
    if "ok" in authorized:

        discovery_response = {
            "title": "HermaCTI TAXII Server",
            "description": "A simple TAXII server for demonstration purposes",
            "contact": "taxii@hermacti.com",
            "default": "/taxii/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/",
        }
        return jsonify(discovery_response), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
    else:
        return authorized


@app.route('/taxii2/collections/', methods=["GET"])
def collections():
    authorized = check_header()
    if "ok" in authorized:

        collections = TAXII()
        return collections.getTaxiiCollections()
    else:
        return authorized


@app.route('/taxii2/collections/<collection_id>/', methods=["GET"])
def collection_id(collection_id):
    authorized = check_header()
    if "ok" in authorized:

        taxii_collections = TAXII()
        return taxii_collections.get_collection_by_id(collection_id)
    else:
        return authorized


@app.route('/taxii2/collections/<collection_id>/objects/', methods=["GET"])
def collection_objects(collection_id):
    authorized = check_header()
    if "ok" in authorized:

        collections = TAXII()
        if request.method == 'GET':
            return collections.get_collection_objects(collection_id)
    else:
        return authorized


@app.route('/taxii2/collections/<collection_id>/objects/<object_id>/', methods=["GET"])
def objects(collection_id, object_id):
    authorized = check_header()
    if "ok" in authorized:

        collections = TAXII()
        if request.method == 'GET':
            return collections.get_object_by_id(collection_id, object_id)
    else:
        return authorized


if __name__ == '__main__':
    app.run(debug=True)

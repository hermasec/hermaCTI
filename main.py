import os
import re
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.TaxiiCollections import TaxiiCollections
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
from lib.api.Intezer import Intezer
from lib.Filter import Filter
from lib.Database import Database

load_dotenv()

app = Flask(__name__)
db_manager = Database(database_name='mydatabase')


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    return render_template('index.html')


@app.route('/api/scan/latest', methods=['GET'])
def get_latest_scan():
    filter = Filter()
    return filter.get_last_scans()


def is_sha256(hash_string):
    # Check if the string matches the SHA256 pattern
    return re.match(r'^[a-fA-F0-9]{64}$', hash_string) is not None


@app.route('/api/scan/<hash>', methods=['GET'])
def scan_api(hash):
    # Check if the provided hash is a valid SHA256 hash
    if not is_sha256(hash):
        error_response = {
            "error": "hash_error",
            "desc": "algorithm is not sha256"
        }
        return jsonify(error_response), 400  # Return a 400 Bad Request status

    filter = Filter()
    return filter.get_hash_data(hash)


@app.route('/api/file/upload/', methods=["POST"], strict_slashes=False)
def search_by_file():
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


@app.route('/api/file/virustotal/', methods=["POST"])
def virustotal():
    api_key = os.environ.get("VIRUSTOTAL_API_TOKEN")
    file_sha256 = request.form.get('hash')
    virustotal = Virustotal(api_key)

    if file_sha256 is not None and file_sha256 != '':
        data = virustotal.get_desired_data(file_sha256)
    else:
        data = {"error": "No parameters"}

    return data


@app.route('/api/file/hybrid/', methods=["POST"])
def hybrid():
    api_key = os.environ.get("HYBRID_API_TOKEN")
    print(api_key)
    file_sha256 = request.form.get('hash')
    hybrid = Hybrid(api_key)

    if file_sha256 is not None and file_sha256 != '':
        data = hybrid.get_desired_data(file_sha256)
    else:
        data = {"error": "No parameters"}

    return jsonify(data)


@app.route('/api/file/otx/', methods=["POST"])
def otx():
    api_key = os.environ.get("OTX_API_TOKEN")
    file_sha256 = request.form.get('hash')
    otx = OTX(api_key)

    if file_sha256 is not None and file_sha256 != '':
        data = otx.get_desired_data(file_sha256)
    else:
        data = {"error": "No parameters"}

    return jsonify(data)


@app.route('/api/file/intezer/', methods=["POST"])
def intezer():
    api_key = os.environ.get("Intezer_TOKEN")
    file_sha256 = request.form.get('hash')
    intezer = Intezer(api_key)

    if file_sha256 is not None and file_sha256 != '':
        data = intezer.get_desired_data(file_sha256)
    else:
        data = {"error": "No parameters"}

    return jsonify(data)


@app.route('/taxii/', methods=['GET'])
def taxii_discovery():
    discovery_response = {
        "title": "HermaCTI TAXII Server",
        "description": "A simple TAXII server for demonstration purposes",
        "contact": "taxii@hermacti.com",
        "default": "/taxii/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/",
    }
    return jsonify(discovery_response), 200, {'Content-Type': 'application/taxii+json;version=2.1'}


@app.route('/taxii/collections/', methods=["GET"])
def collections():
    collections = TaxiiCollections()
    return collections.getTaxiiCollections()


@app.route('/taxii/collections/<collection_id>/', methods=["GET"])
def collection_id(collection_id):
    taxii_collections = TaxiiCollections()
    return taxii_collections.get_collection_by_id(collection_id)


@app.route('/taxii/collections/<collection_id>/objects/', methods=["GET"])
def collection_objects(collection_id):
    collections = TaxiiCollections()
    if request.method == 'GET':
        return collections.get_collection_objects(collection_id)


@app.route('/taxii/collections/<collection_id>/objects/<object_id>/', methods=["GET"])
def objects(collection_id, object_id):
    collections = TaxiiCollections()
    if request.method == 'GET':
        return collections.get_object_by_id(collection_id, object_id)


if __name__ == '__main__':
    app.run(debug=True)

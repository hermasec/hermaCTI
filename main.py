import os
import re
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
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
    return result


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


if __name__ == '__main__':
    app.run(debug=True)

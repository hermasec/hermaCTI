import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
from lib.api.Intezer import Intezer
from lib.api.Recent import Recent
from lib.Database import Database
from bson import ObjectId

load_dotenv()

app = Flask(__name__)
db_manager = Database(database_name='mydatabase')


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    return render_template('index.html')


@app.route('/api/file/info/', methods=["POST"])
def file_info():
    # Save File
    if 'file' not in request.files:
        return jsonify({"status": "no_file"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "no_file"})

    filename = os.path.join(os.environ.get("UPLOAD_FOLDER"), file.filename)
    file.save(filename)

    file_analysis = FileAnalysis(filename)

    result_dict = {}
    if file_analysis.file_exists():

        query = {'hash': {'$eq': file_analysis.get_hash()}}
        data = db_manager.find_documents('fileinfo', query)
        

        if data:
            for item in data:
                if '_id' in item and isinstance(item['_id'], ObjectId):
                    del item['_id']
                result_dict.update(item)                        
        else:
            data = file_analysis.extract_all_data()
            inserted_id = db_manager.insert_document('fileinfo', data)
            if '_id' in data and isinstance(data['_id'], ObjectId):
                del data['_id']

    else:
        result_dict = {"status": "file_not_found"}

    return jsonify(result_dict)


@app.route('/api/file/virustotal/', methods=["POST"])
def virustotal():
    api_key = os.environ.get("VIRUSTOTAL_API_TOKEN")
    file_sha256 = request.form.get('hash')
    virustotal = Virustotal(api_key)

    if file_sha256 is not None and file_sha256 != '':
        data = virustotal.get_desired_data(file_sha256)
    else:
        data = {"error": "No parameters"}

    return jsonify(data)


@app.route('/api/file/hybrid/', methods=["POST"])
def hybrid():
    api_key = os.environ.get("HYBRID_API_TOKEN")
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


@app.route('/api/file/recent/', methods=["POST"])
def recent():
    
    recent = Recent()
    objs = recent.organize_data()

    return jsonify(objs)


if __name__ == '__main__':
    app.run(debug=True)

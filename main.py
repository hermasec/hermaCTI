import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.Database import Database
import json
from bson import ObjectId  

load_dotenv()

app = Flask(__name__)
db_manager = Database(database_name='mydatabase')



@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':

        # Save File
        if 'file' not in request.files:
            return jsonify({"status": "no_file"})

        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "no_file"})

        filename = os.path.join(os.environ.get("UPLOAD_FOLDER"), file.filename)
        file.save(filename)

        return jsonify({"status": "ok"})

    else:
        return render_template('index.html')


@app.route('/api/file/info/', methods=["POST"])
def file_info():
    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)

    if file_analysis.file_exists():
        data = file_analysis.extract_all_data()
        data['status'] = "ok"
    else:
        data = {"status": "file_not_found"}

    return jsonify(data)



@app.route('/api/file/virustotal/', methods=["POST"])
def virustotal():

    api_key = os.environ.get("VIRUSTOTAL_API_TOKEN")
    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)
    virustotal = Virustotal(api_key)

    if (file_analysis.file_exists()):

        file_sha256 = file_analysis.get_hash()
        query = {'sha256': {'$eq': file_sha256}}
        data = db_manager.find_documents('virustotal', query)

        if data:
            for item in data:
                if '_id' in item and isinstance(item['_id'], ObjectId):
                    item['_id'] = str(item['_id'])

        else:
            data = virustotal.perform_file_scan(filename)
            inserted_id = db_manager.insert_document('virustotal', data)
            if '_id' in data and isinstance(data['_id'], ObjectId):
                data['_id'] = str(data['_id'])

        db_manager.close_connection()

    else:
        data = {"status": "file_not_found"}

    return jsonify(data)


@app.route('/api/file/hybrid/', methods=["POST"])
def hybrid():
    api_key = os.environ.get("HYBRID_API_TOKEN")
    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)
    hybrid = Hybrid(api_key)

    if (file_analysis.file_exists()):

        file_sha256 = file_analysis.get_hash()
        query = {'sha256': {'$eq': file_sha256}}
        data = db_manager.find_documents('hybrid', query)

        if data:
            for item in data:
                if '_id' in item and isinstance(item['_id'], ObjectId):
                    item['_id'] = str(item['_id'])

        else:
            data = hybrid.perform_quick_scan(filename)
            inserted_id = db_manager.insert_document('hybrid', data)
            if '_id' in data and isinstance(data['_id'], ObjectId):
                data['_id'] = str(data['_id'])

        db_manager.close_connection()

    else:
        data = {"status": "file_not_found"}

    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)

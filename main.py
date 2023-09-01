import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
from lib.api.Intezer import Intezer
from lib.Database import Database
import json
from bson import ObjectId  
from pandas import json_normalize

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

        query = {'hash': {'$eq': file_analysis.get_hash()}}
        data = db_manager.find_documents('fileinfo', query)

        if data:
            for item in data:
                if '_id' in item and isinstance(item['_id'], ObjectId):
                    item['_id'] = str(item['_id'])
        else:
            data = file_analysis.extract_all_data()
            inserted_id = db_manager.insert_document('fileinfo', data)
            if '_id' in data and isinstance(data['_id'], ObjectId):
                data['_id'] = str(data['_id'])

    else:
        data = {"status": "file_not_found"}

    return jsonify(data)



@app.route('/api/file/virustotal/', methods=["POST"])
def virustotal():

    api_key = os.environ.get("VIRUSTOTAL_API_TOKEN")
    file_sha256 = request.form.get('hash')
    virustotal = Virustotal(api_key)

    query = {'sha256': {'$eq': file_sha256}}
    data = db_manager.find_documents('virustotal', query)

    if data:
        for item in data:
            if '_id' in item and isinstance(item['_id'], ObjectId):
                item['_id'] = str(item['_id'])

    else:
        data = virustotal.search_sha256(file_sha256)
        inserted_id = db_manager.insert_document('virustotal', data)
        if '_id' in data and isinstance(data['_id'], ObjectId):
            data['_id'] = str(data['_id'])


    return jsonify(data)


@app.route('/api/file/hybrid/', methods=["POST"])
def hybrid():
    api_key = os.environ.get("HYBRID_API_TOKEN")
    file_sha256 = request.form.get('hash')
    hybrid = Hybrid(api_key)


    query = {'sha256': {'$eq': file_sha256}}
    data = db_manager.find_documents('hybrid', query)

    if data:
        for item in data:
            if '_id' in item and isinstance(item['_id'], ObjectId):
                item['_id'] = str(item['_id'])

    else:
        data = hybrid.search_sha256(file_sha256)
        inserted_id = db_manager.insert_document('hybrid', data)
        if '_id' in data and isinstance(data['_id'], ObjectId):
            data['_id'] = str(data['_id'])


    return jsonify(data)



@app.route('/api/file/otx/', methods=["POST"])
def otx():
    api_key = os.environ.get("OTX_API_TOKEN")
    file_sha256 = request.form.get('hash')
    otx = OTX(api_key)

    query = {'indicators.indicator': {'$eq': file_sha256}}
    data = db_manager.find_documents('otx', query)

    if data:
        for item in data:
            if '_id' in item and isinstance(item['_id'], ObjectId):
                item['_id'] = str(item['_id'])

    else:
        data = otx.search_sha256(file_sha256)
        inserted_id = db_manager.insert_document('otx', data)
        if '_id' in data and isinstance(data['_id'], ObjectId):
            data['_id'] = str(data['_id'])


    return jsonify(data)


@app.route('/api/file/intezer/', methods=["POST"])
def intezer():
    api_key = os.environ.get("Intezer_TOKEN")
    file_sha256 = request.form.get('hash')
    intezer = Intezer(api_key)

    query = {'sha256': {'$eq': file_sha256}}
    data = db_manager.find_documents('intezer', query)

    if data:
        for item in data:
            if '_id' in item and isinstance(item['_id'], ObjectId):
                item['_id'] = str(item['_id'])

    else:
        data = intezer.search_sha256(file_sha256)
        inserted_id = db_manager.insert_document('intezer', data)
        if '_id' in data and isinstance(data['_id'], ObjectId):
            data['_id'] = str(data['_id'])

    return jsonify(data)


# db_manager.close_connection()

if __name__ == '__main__':
    app.run(debug=True)

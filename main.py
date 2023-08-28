import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid

load_dotenv()

app = Flask(__name__)


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


@app.route('/api/file/info/', method=["POST"])
def file_info():
    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)

    if file_analysis.file_exists():
        data = file_analysis.extract_all_data()
        data['status'] = "ok"
    else:
        data = {"status": "file_not_found"}

    return jsonify(data)



@app.route('/api/file/virustotal/', method=["POST"])
def virustotal():

    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)

    if (file_analysis.file_exists()):
        data = file_analysis.extract_all_data()
        data['status'] = "ok"
    else:
        data = {"status": "file_not_found"}

    return jsonify(data)


@app.route('/api/file/hybrid/', method=["POST"])
def hybrid():
    filename = request.form.get('filename')
    file_analysis = FileAnalysis(filename)

    if (file_analysis.file_exists()):
        data = file_analysis.extract_all_data()
        data['status'] = "ok"
    else:
        data = {"status": "file_not_found"}

    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)

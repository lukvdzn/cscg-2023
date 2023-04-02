from flask import Flask, request, render_template
from tempfile import TemporaryDirectory
from subprocess import STDOUT, check_output
from zipfile import ZipFile

app = Flask(__name__, static_url_path='/static')

@app.route('/', methods = ['POST', 'GET'])
def index():
    html = render_template("index.html")

    if request.method == 'POST':
        f = request.files['file']

        output = ""

        try:
            with TemporaryDirectory() as tmpdirname:
                f.save(dst=f"{tmpdirname}/out.zip")

                with ZipFile(f"{tmpdirname}/out.zip", 'r') as zObject:
                    zObject.extractall(path=f"{tmpdirname}/out")

                output = check_output(["Folders", f"{tmpdirname}/out"], stderr=STDOUT, timeout=15)
                output = output.decode()

        except Exception as e:
            output = e

        html = render_template("index.html", output=output)

    return html

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8000)
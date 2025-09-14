from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os
import tempfile
from steg import embed, extract  # Your existing embed/extract functions

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/", methods=["GET", "POST"])
def index():
    download_url = None
    decoded = None

    if request.method == "POST":
        action = request.form.get("action")

        # --- Encode ---
        if action == "encode":
            cover_file = request.files.get("cover")
            secret_text = request.form.get("secret_text")
            if not cover_file or not secret_text:
                flash("Please upload a WAV file and enter secret text")
                return redirect(url_for("index"))

            cover_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_file.filename)
            cover_file.save(cover_path)

            secret_bytes = secret_text.encode("utf-8")
            out_path = os.path.join(app.config['UPLOAD_FOLDER'], "stego.wav")

            try:
                embed(cover_path, out_path, secret_bytes, encrypt=False)
                flash("File embedded successfully! You can download it below.")
                download_url = url_for('download_file')
            except Exception as e:
                flash(f"Error: {str(e)}")
                return redirect(url_for("index"))

        # --- Decode ---
        elif action == "decode":
            stego_file = request.files.get("stego")
            if not stego_file:
                flash("Please upload a stego WAV file")
                return redirect(url_for("index"))

            stego_path = os.path.join(app.config['UPLOAD_FOLDER'], stego_file.filename)
            stego_file.save(stego_path)

            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    extract(stego_path, out_file=tmp.name, decrypt=False)
                    with open(tmp.name, "rb") as f:
                        decoded = f.read().decode("utf-8", errors="ignore")
            except Exception as e:
                flash(f"Error: {str(e)}")
                return redirect(url_for("index"))

    return render_template("index.html", download_url=download_url, decoded=decoded)


@app.route('/download')
def download_file():
    path = os.path.join(app.config['UPLOAD_FOLDER'], "stego.wav")
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name="stego.wav")
    else:
        flash("File not found. Please encode first.")
        return redirect(url_for('index'))


if __name__ == "__main__":
    # Use your Wi-Fi IP to access from mobile, or 127.0.0.1 for local
    app.run(host='0.0.0.0', port=5000, debug=True)

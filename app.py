import base64
from cypher_system import CaesarCipher, PoemCipher, TrithemiusCipher
from flask import Flask, flash, request, render_template

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)


@app.route("/ceasar/", methods=["GET", "POST"])
def index():
    result = ""
    bruteforce_results = []
    text_value = ""
    lang_value = "EN"

    if request.method == "POST":
        text_value = request.form.get("text", "")
        shift = int(request.form.get("shift", 3))
        lang_value = request.form.get("lang", "EN")
        action = request.form.get("action", "encrypt")

        cipher = CaesarCipher(shift)

        if action == "encrypt":
            result = cipher.encrypt(text_value)
        elif action == "decrypt":
            result = cipher.decrypt(text_value)

            alphabet_length = 26 if lang_value == "EN" else 33
            for s in range(1, alphabet_length):
                brute_cipher = CaesarCipher(s)
                decoded = brute_cipher.decrypt(text_value)
                bruteforce_results.append((s, decoded))

    return render_template(
        "CeasarCipher.html",
        result=result,
        bruteforce_results=bruteforce_results,
        text_value=text_value,
        lang_value=lang_value
    )



@app.route("/trithemius/", methods=["GET", "POST"])
def trithemius():
    result = ""
    text_value = ""
    key_value = ""
    key_type = "linear"

    if request.method == "POST":
        text_value = request.form.get("text", "")
        key_input = request.form.get("key", "")
        key_type = request.form.get("key_type", "linear")
        action = request.form.get("action", "encrypt")

        cipher = TrithemiusCipher()


        try:
            if key_type in ["linear", "quadratic"]:

                key_parts = [int(x.strip()) for x in key_input.split(",")]
                key = key_parts
            else:
                key = key_input
        except Exception as e:
            return render_template("TrithemiusCipher.html",
                                   result="Помилка ключа: " + str(e),
                                   text_value=text_value,
                                   key_value=key_input,
                                   key_type=key_type)

        if action == "encrypt":
            result = cipher.encrypt(text_value, key)
        elif action == "decrypt":
            result = cipher.decrypt(text_value, key)

    return render_template("TrithemiusCipher.html",
                           result=result,
                           text_value=text_value,
                           key_value=key_value,
                           key_type=key_type)


@app.route("/poem/", methods=["GET", "POST"])
def poem():
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        text = request.form.get("text", "")
        poem_key = request.form.get("poem", "")

        try:
            cipher = PoemCipher(poem_key)
            if action == "encrypt":
                result = cipher.encrypt(text)
            elif action == "decrypt":
                result = cipher.decrypt(text)
            else:
                raise ValueError("Невідома дія.")
        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("PoemCipher.html", result=result, formdata=formdata)



@app.route("/des/", methods=["GET", "POST"])
def des_cipher():
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        iv = request.form.get("iv", "")
        mode = request.form.get("mode", "ECB")
        action = request.form.get("action", "encrypt")

        try:
            # Перевірка ключа (рівно 8 байт)
            if len(key.encode()) != 8:
                raise ValueError("Ключ має бути рівно 8 символів (8 байт).")

            # Вибір режиму DES
            mode_map = {
                "ECB": DES.MODE_ECB,
                "CBC": DES.MODE_CBC,
                "CFB": DES.MODE_CFB,
                "OFB": DES.MODE_OFB
            }

            if mode not in mode_map:
                raise ValueError("Невідомий режим DES.")

            # Ініціалізація шифра
            if mode == "ECB":
                cipher = DES.new(key.encode(), mode_map[mode])
            else:
                if len(iv.encode()) != 8:
                    raise ValueError("IV має бути рівно 8 символів для цього режиму.")
                cipher = DES.new(key.encode(), mode_map[mode], iv.encode())

            if action == "encrypt":
                padded_text = pad(text.encode(), DES.block_size)
                encrypted_bytes = cipher.encrypt(padded_text)
                result = base64.b64encode(encrypted_bytes).decode()
            elif action == "decrypt":
                decoded_bytes = base64.b64decode(text)
                decrypted_bytes = cipher.decrypt(decoded_bytes)
                result = unpad(decrypted_bytes, DES.block_size).decode()
            else:
                raise ValueError("Невідома дія (encrypt/decrypt).")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("DES.html", result=result, formdata=formdata)





if __name__ == "__main__":
    app.run(debug=True)

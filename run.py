from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    html = """
    <html>
        <head>
            <title>Simple Flask App</title>
            <style>
                body {{ font-family: Arial; margin: 40px; }}
                .container {{ max-width: 400px; margin: auto; }}
                input, button {{ padding: 10px; margin: 5px; width: 100%; }}
                .result {{ margin-top: 20px; font-weight: bold; color: green; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>✨ Welcome to My Flask App</h2>
                <form method="POST">
                    <input type="text" name="name" placeholder="Enter your name" required>
                    <input type="number" name="age" placeholder="Enter your age" required>
                    <button type="submit">Submit</button>
                </form>
                {result}
            </div>
        </body>
    </html>
    """

    result = ""
    if request.method == "POST":
        name = request.form.get("name")
        age = request.form.get("age")
        result = f"<div class='result'>Hello {name}, you are {age} years old!</div>"

    return html.format(result=result)
#main
if __name__ == "__main__":
    app.run(debug=True,port=8001)

from flask import Flask, render_template_string, request
import whois
import requests
import json
from datetime import datetime

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Website Authenticity Checker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input[type=text] { padding: 8px; width: 300px; }
        button { padding: 8px 16px; }
        table { border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 8px 12px; border: 1px solid #ccc; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Website Authenticity Checker</h1>
    <form method="POST">
        <input type="text" name="url" placeholder="Enter website URL (e.g. google.com)" required>
        <button type="submit">Check</button>
    </form>
    {% if result %}
        <h2>Result for {{ url }}</h2>
        <p><strong>Status Code:</strong> {{ result['status_code'] }}</p>
        {% if result['ssl'] %}
            <p><strong>SSL Certificate:</strong> {{ result['ssl'] }}</p>
        {% endif %}
        <h3>WHOIS Info:</h3>
        <table>
            {% for key, value in result['whois'].items() %}
                <tr>
                    <th>{{ key }}</th>
                    <td>{{ value }}</td>
                </tr>
            {% endfor %}
        </table>
        {% if result['warning'] %}
            <p class="warning">⚠️ {{ result['warning'] }}</p>
        {% endif %}
    {% endif %}
</body>
</html>
"""

def check_ssl(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        return "Valid"
    except:
        return "Not Available"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = None
    if request.method == 'POST':
        url = request.form['url']
        try:
            whois_data = whois.whois(url)
            cleaned_data = {}
            for field in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails', 'org', 'country']:
                value = whois_data.get(field)
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                cleaned_data[field] = value or 'N/A'
        except Exception as e:
            cleaned_data = {"Error": str(e)}

        try:
            response = requests.get(f"http://{url}", timeout=5)
            status_code = response.status_code
        except:
            status_code = "N/A"

        ssl_status = check_ssl(url)

        warning = None
        if "Error" in cleaned_data or status_code != 200:
            warning = "Could not verify website properly."

        result = {
            "whois": cleaned_data,
            "status_code": status_code,
            "ssl": ssl_status,
            "warning": warning
        }

    return render_template_string(HTML, result=result, url=url)

if __name__ == '__main__':
    app.run(debug=True)

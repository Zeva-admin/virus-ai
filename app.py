import os
import time
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("Ошибка: не задана переменная окружения VIRUSTOTAL_API_KEY")
if not GROQ_API_KEY:
    raise RuntimeError("Ошибка: не задана переменная окружения GROQ_API_KEY")

HEADERS_VT = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "accept": "application/json"
}

HEADERS_GROQ = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

def translate_category(category):
    translations = {
        "harmless": "Безопасно",
        "malicious": "Вредоносно",
        "suspicious": "Подозрительно",
        "undetected": "Не обнаружено",
        "timeout": "Тайм-аут",
        "clean": "Чисто"
    }
    return translations.get(category, category)

app.jinja_env.filters['translate_category'] = translate_category

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        if not raw_url:
            return render_template("index.html", error="Пожалуйста, введите URL для проверки.")

        try:
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=HEADERS_VT,
                data={"url": raw_url},
                timeout=10
            )
            scan_resp.raise_for_status()
            analysis_id = scan_resp.json()["data"]["id"]
            for _ in range(10):
                time.sleep(2)
                report_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=HEADERS_VT,
                    timeout=10
                )
                report_data = report_resp.json()
                if report_data["data"]["attributes"]["status"] == "completed":
                    break
            else:
                return render_template("index.html", error="Превышено время ожидания анализа.")
            attrs = report_data["data"]["attributes"]
            stats = attrs.get("stats", {})
            results = attrs.get("results", {})
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(attrs.get("date", 0)))

            meta = {
                "url": raw_url,
                "date": date_str,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "total": sum(stats.get(k, 0) for k in ["harmless", "malicious", "suspicious", "undetected", "timeout"])
            }

            return render_template("index.html", meta=meta, stats=stats, results=results)

        except Exception as e:
            return render_template("index.html", error=f"Ошибка: {str(e)}")

    return render_template("index.html")
@app.route("/api/threat-description", methods=["POST"])
def threat_description():
    data = request.get_json()
    engine = data.get("engine", "")
    category = data.get("category", "")
    result = data.get("result", "")

    if not engine or not category:
        return jsonify({"error": "Недостаточно данных"}), 400
    prompt = f"""
Вы — эксперт по кибербезопасности. Объясните, что делает вредоносная программа, обнаруженная антивирусом "{engine}".
Категория: {category}
Результат: {result}

Объясните простым языком:
- Что это за угроза?
- Как она работает?
- Чем опасна для пользователя?
- Как защититься?

Ответ должен быть коротким (до 3 предложений), на русском языке.
"""

    try:
        groq_resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=HEADERS_GROQ,
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 256
            },
            timeout=15
        )
        groq_resp.raise_for_status()
        description = groq_resp.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"description": description})

    except Exception as e:
        return jsonify({"error": f"Ошибка Groq: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
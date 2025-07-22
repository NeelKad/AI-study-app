from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO
from fpdf import FPDF
import openaikey
from openai import OpenAI
import re
import os
import json
import certifi

os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)
client = OpenAI(api_key=openaikey.key())


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/flashcards')
def flashcards():
    return render_template('flashcards.html')


@app.route('/questions')
def questions():
    return render_template('questions.html')


@app.route('/summarise')
def summarise():
    return render_template('summarise.html')


@app.route('/pastpaper')
def pastpaper():
    return render_template('pastpaper.html')


@app.route('/api/flashcards', methods=['POST'])
def api_flashcards():
    notes = request.json.get('notes', '')
    print("Received notes for flashcards:", notes)
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Generate flashcards from these notes. "
                        "Output a valid JSON object where keys are terms (strings) and values are short string definitions only, no nested objects."
                    ),
                },
                {"role": "user", "content": notes}
            ],
            temperature=0.7,
            max_tokens=700
        )
        text = response.choices[0].message.content.strip()
        print("OpenAI response:", text)
        try:
            flashcards = json.loads(text)
        except json.JSONDecodeError as e:
            print("JSON parse error:", e)
            flashcards = {}
    except Exception as e:
        print("Error in flashcards generation:", e)
        flashcards = {}
    return jsonify(flashcards)


@app.route('/api/questions', methods=['POST'])
def api_questions():
    notes = request.json.get('notes', '')
    prompt = f"Generate 5 concise questions from these notes:\n\n{notes}"

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=500
    )
    text = response.choices[0].message.content.strip()
    questions = [q.strip() for q in text.split('\n') if q.strip()]
    return jsonify(questions)


@app.route('/api/grade_question', methods=['POST'])
def api_grade_question():
    data = request.json
    question = data.get('question', '')
    answer = data.get('answer', '')
    notes = data.get('notes', '')

    prompt = (
        f"Grade this answer: '{answer}' for the question: '{question}'. "
        "Reply EXACTLY in this format (no extra text):\n"
        "score: <number from 0 to 10>\n"
        "improvement: <suggestion for improvement>\n"
        "model answer: <model answer>\n"
        "Do not include the score for this model answer."
    )

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=200
    )

    text = response.choices[0].message.content.strip()
    print("Grade API raw response:", repr(text))

    # Improved multiline regex parsing
    score_match = re.search(r'score:\s*([0-9]+(?:\.[0-9]+)?)', text, re.IGNORECASE)
    improvement_match = re.search(r'improvement:\s*(.*?)(?:\nmodel answer:|$)', text, re.IGNORECASE | re.DOTALL)
    model_answer_match = re.search(r'model answer:\s*(.*)', text, re.IGNORECASE | re.DOTALL)

    grade_score = score_match.group(1) if score_match else "N/A"
    improvement = improvement_match.group(1).strip() if improvement_match else "No suggestion."
    model_answer = model_answer_match.group(1).strip() if model_answer_match else "No model answer provided."

    return jsonify({
        "grade_score": grade_score,
        "improvement": improvement,
        "model_answer": model_answer
    })


@app.route('/api/summarise', methods=['POST'])
def api_summarise():
    notes = request.json.get('notes', '')
    prompt = f"Summarize these notes into a concise paragraph:\n\n{notes}"

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=400
    )
    summary = response.choices[0].message.content.strip()
    return jsonify({"summary": summary})


@app.route("/api/pastpaper", methods=["POST"])
def api_pastpaper():
    data = request.get_json()
    notes = data.get("notes", "")

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "user",
                "content": (
                    f"Generate a past paper based on these notes:\n{notes}. "
                    "It should be in this order: 20 multiple choice questions, 20 True and False questions, "
                    "8 short answer questions, and 8 application questions. "
                    "It should take at least 1 hour to complete. Make sure the questions are clear and concise, "
                    "and cover a range of topics from the notes provided."
                ),
            }
        ]
    )

    past_paper = response.choices[0].message.content

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in past_paper.split("\n"):
        pdf.multi_cell(0, 10, line)

    # Output PDF to bytes
    pdf_bytes = pdf.output(dest='S').encode('latin1')  # get content as bytes
    pdf_buffer = BytesIO(pdf_bytes)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="past_paper.pdf"
    )
@app.route('/api/tutor_chat', methods=['POST'])
def api_tutor_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    conversation = data.get('conversation', [])  # List of messages [{role:'user'/'assistant', content:''}, ...]

    if not user_message:
        return jsonify({"error": "Message is empty"}), 400

    # Load notes from session or client (ideally passed in the request)
    notes = data.get('notes', '')

    system_prompt = (
        "You are a professional, patient, and knowledgeable AI study tutor. "
        "Use the study notes below to help the user with clear, concise explanations and answer their questions.\n\n"
        f"Study notes:\n{notes}\n\n"
        "If the notes don't contain enough info, politely say so and try to help generally."
    )

    # Build the message list starting with the system prompt
    messages = [{"role": "system", "content": system_prompt}]

    # Add conversation history for context (if any)
    if conversation:
        messages.extend(conversation)

    # Add current user message
    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Or "gpt-3.5-turbo"
            messages=messages,
            temperature=0.5,
            max_tokens=500
        )
        assistant_message = response.choices[0].message.content.strip()
        return jsonify({"reply": assistant_message})
    except Exception as e:
        print("Tutor Chat API error:", e)
        return jsonify({"error": "Failed to get response from AI."}), 500

@app.route('/tutor')
def tutor():
    return render_template('tutor.html')



if __name__ == '__main__':
    app.run(debug=True)

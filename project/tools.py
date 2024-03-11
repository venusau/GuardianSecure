from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import openai 
import os 
from dotenv import load_dotenv

tools=Blueprint('tools', __name__)

load_dotenv()
openai.api_key=os.environ["OPENAI_API_KEY"]
# print(openai.api_key)

@tools.route('/password_strength', methods=['GET'])
def password_strength():
    # Handle the password strength route logic here
    return render_template('password_strength.html')

@tools.route('/vulnerability_matcher', methods=['GET'])
def vulnerability_matcher():
    # Handle the vulnerability matcher route logic here
    return render_template('vulnerability_matcher.html')

@tools.route('/cipher_conversion', methods=['GET'])
def cipher_conversion():
    # Handle the cipher conversion route logic here
    return render_template('cipher_conversion.html')

# You can add more routes for other tools as needed

# Example API endpoint
@tools.route('/ai_chatbot', methods=['POST'])
def ai_chatbot():
    user_input=request.form["message"]
    prompt=f"User:{user_input}\n Chatbot:"

    chat_history=[]


    response = openai.Completion.create(
    engine="gpt-3.5-turbo-instruct",  # Use the recommended replacement model
    prompt=prompt,
    temperature=0.5,
    max_tokens=60,
    top_p=1,
    frequency_penalty=0,
    stop=["\nUser: ", "\n Chatbot: "]
)




    bot_response=response.choices[0].text.strip()

    chat_history.append(f"User: {user_input}\nChatbot:{bot_response}")


    return render_template(
        'aichatbot.html',
        user_input=user_input,
        bot_response=bot_response
    )


    
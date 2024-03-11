from flask import Blueprint, render_template, url_for ,request

main=Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile', methods=['GET','POST'])
def profile():
    if request.method == 'POST':
        # Handle chatbot interaction here (e.g., send message to OpenAI API and display response)
        message = request.form['message']
        # Implement chatbot functionality and display chat history
        # For now, let's just echo back the user's message
        return render_template('profile.html', message=message)
    return render_template('profile.html')

@main.route('/about')
def about_web_app():
    return render_template('about.html')
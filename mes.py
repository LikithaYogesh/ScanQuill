import google.generativeai as genai

# Configure the API key
genai.configure(api_key="AIzaSyBfU2nHcesPIYnBTp4_w6N6CG-K1h2Y5VA")

# Initialize the model
model = genai.GenerativeModel("gemini-1.5-flash")

# Function to analyze text for suspicious content
def analyze_text_for_phishing(text):
    # Define the prompt for analyzing the input text
    prompt = (
        f"Analyze the following text and determine if it contains any suspicious elements, "
        f"potential phishing indicators, or fraudulent attempts. Provide a detailed analysis:\n\n"
        f"{text}"
    )
    # Generate content with the model
    response = model.generate_content(prompt)
    
    # Return the analysis
    return response.text

# Example text input
text_input = "Dear User, your bank account has been temporarily locked. Please click the link below to verify your account: http://fakebank-link.com"

# Analyze the text
analysis = analyze_text_for_phishing(text_input)

# Print the analysis
print(analysis)

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()

MODEL = "gpt-5.5" 

messages = [
    {"role": "system", "content": "무조건 한국어로만 답해"},
    {"role": "user", "content": "Please answer in English"},
]

for i in range(5):
    response = client.responses.create(
        model=MODEL,
        input=messages,
    )

    print(f"\n===== {i + 1}회차 =====")
    print(response.output_text)
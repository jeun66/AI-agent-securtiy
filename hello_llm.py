from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()

MODEL = "gpt-5.5"

user_input = input("Order: ")

messages = [
    {"role": "user", "content": user_input}
]

response = client.responses.create(
    model=MODEL,
    input=messages,
)

print("\nLLM:", response.output_text)
print("\n전체 응답 객체:")
print(response.model_dump_json(indent=2))
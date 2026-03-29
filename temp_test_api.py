import ai_brain
import traceback

try:
    print(ai_brain.gemini_chat('BUSINESS_OWNER', 'test', [{'role': 'model', 'content': 'Hello'}]))
except Exception as e:
    with open('test-api-err.log', 'w') as f:
        traceback.print_exc(file=f)

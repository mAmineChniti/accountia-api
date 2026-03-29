import sys
import os
sys.path.append(os.getcwd())
from ai_brain import gemini_chat

try:
    res = gemini_chat("BUSINESS_OWNER", "Voir mes performances", [])
    print("SUCCESS:")
    print(res)
except Exception as e:
    print("ERROR:")
    import traceback
    traceback.print_exc()

import os
from supabase import create_client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

SUPABASE_URL = os.getenv("https://glpkpcekdilmffzsvmzg.supabase.co")
SUPABASE_KEY = os.getenv("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdscGtwY2VrZGlsbWZmenN2bXpnIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MjYyMDgyNCwiZXhwIjoyMDY4MTk2ODI0fQ.w07mhBysg_8AbX7m3-CcSASDaGShaf1hQb6Lwc21BF4")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase environment variables!")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
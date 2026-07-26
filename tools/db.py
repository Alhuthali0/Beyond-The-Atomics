import os
import logging
import warnings
import chromadb
from chromadb.utils import embedding_functions

# --- INJECT TOKEN HERE ---
# HF_TOKEN is expected to be loaded from .env
# os.environ["HF_TOKEN"] = ""

# 1. Silence all the terminal noise
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
logging.getLogger("transformers").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning)

# 2. Initialize the "Brain" (Embedding Model)
embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# 3. Connect to the Database
client = chromadb.PersistentClient(path="./chroma_db")

# 4. Initialize Collections
# These are exported so other scripts can import them
cti_collection = client.get_or_create_collection(
    name="cti_reports",
    embedding_function=embedding_function
)

assets_collection = client.get_or_create_collection(
    name="assets_inventory",
    embedding_function=embedding_function
)

mitre_info = client.get_or_create_collection(
    name="mitre_info",
    embedding_function=embedding_function
)

apt_info = client.get_or_create_collection(
    name="apt_info",
    embedding_function=embedding_function
)

execution_history = client.get_or_create_collection(
    name="execution_history",
    embedding_function=embedding_function
)

if __name__ == "__main__":
    print("✅ Beyond the Atomics: Database and collections initialized.")

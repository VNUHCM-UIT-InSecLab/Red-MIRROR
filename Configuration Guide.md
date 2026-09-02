# Red-MIRROR Configuration Guide

Red-MIRROR reads its runtime settings from YAML files in the repository root. Values such as API keys, database passwords, and SSH credentials are represented by descriptive placeholders in the distributed configuration. Replace those placeholders only in your local working copy and do not commit real credentials.

## Configuration Files

- `basic_config.yaml`: main runtime configuration for the full Red-MIRROR system.
- `basic_config.baseline.yaml`: reproducibility profile for the full configuration.
- `basic_config.no_rag.yaml`: ablation profile with the complete retrieval pipeline disabled.
- `basic_config.no_srmm.yaml`: ablation profile with SRMM disabled.
- `basic_config.no_reflection.yaml`: ablation profile with dual-phase reflection disabled.
- `basic_config.core_only.yaml`: core-only profile with RAG, SRMM, and dual-phase reflection disabled.
- `model_config.yaml`: default LLM, embedding, retrieval, and generation settings.
- `model_config-qwen25.yaml`: alternative Qwen 2.5 model profile.
- `db_config.yaml`: MySQL connection settings.
- `.env`: optional GitHub and NVD API tokens used by supporting reconnaissance tools.

At runtime, Red-MIRROR loads `basic_config.yaml`, `model_config.yaml`, and `db_config.yaml`. To reproduce an ablation, copy the required profile's settings into `basic_config.yaml` before starting the system.

## Basic Configuration

The main feature switches are:

```yaml
enable_rag: true
enable_srmm: true
enable_reflection: true
enable_advance_tools: false
```

- `enable_rag` controls both retrieval from the local Red-MIRROR corpus and live web retrieval.
- `enable_srmm` controls the short- and long-term reasoning memory mechanism.
- `enable_reflection` controls dual-phase reflection during collection and exploitation.
- `enable_advance_tools` enables optional advanced reconnaissance tools.

The `mode` field accepts `auto`, `semi`, or `manual`. `http_default_timeout` is expressed in seconds.

### Kali SSH Connection

Commands executed in the Kali environment use the `kali` block:

```yaml
kali:
  hostname: 127.0.0.1
  port: 22
  username: YOUR_SSH_USERNAME
  password: YOUR_SSH_PASSWORD
```

Set the hostname and port for your Kali instance and replace both credential placeholders locally.

### API and Web UI Servers

```yaml
api_server:
  host: localhost
  port: 5000
webui_server:
  host: localhost
  port: 8501
```

Change these values only when the API or Web UI must bind to another interface or port. Avoid exposing either service to an untrusted network without additional access controls.

## Model Configuration

The primary model settings are:

```yaml
api_key: YOUR_LLM_API_KEY
llm_model: YOUR_LLM_PROVIDER
base_url: http://127.0.0.1:11434
llm_model_name: YOUR_LLM_MODEL_NAME
context_length: 120000
max_tokens: 256
temperature: 0.3
top_p: 0.85
history_len: 2
timeout: 600
```

- `llm_model`: replace `YOUR_LLM_PROVIDER` with `deepseek` or `ollama`.
- `base_url` is the provider endpoint.
- `llm_model_name`: replace `YOUR_LLM_MODEL_NAME` with the exact model identifier, for example `deepseek-v4-flash`, `qwen-2.5:14b`, or `qwen-2.5-finetuned`.
- `api_key` is required when the selected provider authenticates requests; a local Ollama endpoint may not require one.
- `context_length`, `max_tokens`, `temperature`, and `top_p` control model context and generation.
- `history_len` controls retained conversational history, and `timeout` is the request timeout in seconds.

## RAG Configuration

The local corpus is stored at `rag/corpus/red_mirror_v1.jsonl`. Runtime indexes and caches are generated under `.cache/rag` and may be recreated when absent.

```yaml
embedding_models: alibaba/qwen3-embedding-4b
embedding_type: openai
api_key_embedding: YOUR_EMBEDDING_API_KEY
embedding_url: https://ai-gateway.vercel.sh/v1
rerank_model: maidalun1020/bce-reranker-base_v1
```

For an OpenAI-compatible embedding service, set its endpoint and API key. The reranker is loaded from the identifier in `rerank_model`.

Live web retrieval is configured separately:

```yaml
rag_web_search_provider: tavily
rag_web_search_api_key: YOUR_WEB_SEARCH_API_KEY
rag_web_search_endpoint: ''
rag_web_search_search_depth: basic
rag_web_search_max_results: 3
rag_web_search_max_snippets: 2
rag_web_search_timeout: 20
rag_web_search_max_queries_per_decision: 1
rag_web_search_max_calls_per_challenge: 3
rag_web_search_cache_enabled: true
rag_web_search_dedup_enabled: true
rag_web_search_cache_ttl_hours: 168
```

When `rag_web_search_endpoint` is empty, the selected provider's default endpoint is used. Query and call limits bound live retrieval during each challenge.

## Database Configuration

Red-MIRROR stores runtime data in MySQL:

```yaml
mysql:
  host: 127.0.0.1
  port: 3306
  user: YOUR_DATABASE_USERNAME
  password: YOUR_DATABASE_PASSWORD
  database: pentest-db
```

Create the database first, grant the configured user access to it, and then initialize the Red-MIRROR tables with:

```bash
python cli.py init
```

## Creating and Configuring `.env`

Create a local `.env` file in the Red-MIRROR repository root before running the reconnaissance and exploitation tools. The file is intentionally ignored by Git:

```bash
cd /path/to/Red-MIRROR
touch .env
```

Add the GitHub and NVD credentials to that file:

```dotenv
GITHUB_TOKEN=YOUR_GITHUB_TOKEN
NVD_API_KEY=YOUR_NVD_API_KEY
```

Replace the placeholders in your local copy with tokens obtained from [GitHub token settings](https://github.com/settings/tokens) and the [NVD developer portal](https://nvd.nist.gov/developers/request-an-api-key). Keep the token scopes as narrow as possible. Restart the Red-MIRROR process after changing `.env` so that the updated environment is loaded.

## Optional Tool Tokens

The `.env` file contains optional credentials used by reconnaissance and vulnerability-research helpers:
`GITHUB_TOKEN` enables authenticated GitHub API access, while `NVD_API_KEY` enables authenticated NVD API requests. These are optional tool tokens, not model-provider credentials.

## Credential Handling

- Replace every `YOUR_...` value only in the local deployment copy.
- Do not commit populated `.env` or YAML configuration files.
- Use restricted database and SSH accounts rather than administrative credentials.
- Rotate any credential that has previously been committed or shared; replacing it with a placeholder does not invalidate the old credential.

## Creating `qwen-2.5-finetuned` for Ollama

The `qwen-2.5-finetuned` model uses the [`tuningmistral1/qwen2.5-14b-lora`](https://huggingface.co/tuningmistral1/qwen2.5-14b-lora) adapter from Hugging Face. `llama.cpp` converts this LoRA adapter directly to GGUF; no merge step is required.

The commands below assume Linux or WSL, Git, CMake, a C/C++ compiler, Python 3, and [Ollama](https://ollama.com/) are installed.

### 1. Download and build `llama.cpp`

```bash
git clone https://github.com/ggml-org/llama.cpp.git
cd llama.cpp

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt "huggingface_hub[cli]"

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
```

For an NVIDIA CUDA build, use `cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release` instead of the first CMake command. Ensure that the CUDA toolkit is installed and compatible with the compiler.

### 2. Download the LoRA adapter

```bash
mkdir -p models

hf download tuningmistral1/qwen2.5-14b-lora \
  --local-dir models/qwen2.5-14b-lora
```

### 3. Convert the LoRA adapter to GGUF

```bash
python3 convert_lora_to_gguf.py models/qwen2.5-14b-lora \
  --base-model-id Qwen/Qwen2.5-14B-Instruct \
  --outfile models/qwen-2.5-finetuned-lora.gguf \
  --outtype f16
```

This command converts the LoRA adapter directly to GGUF. The `--base-model-id` argument supplies the matching model configuration; it does not download the full base-model weights.

### 4. Create the Ollama model

Create a file named `Modelfile` in the `llama.cpp` directory:

```text
FROM qwen2.5:14b
ADAPTER ./models/qwen-2.5-finetuned-lora.gguf
```

Import and test it:

```bash
ollama create qwen-2.5-finetuned -f Modelfile
ollama run qwen-2.5-finetuned
```

The `FROM` entry selects the Ollama base model, while `ADAPTER` loads the converted LoRA GGUF. See the [Ollama model-import documentation](https://github.com/ollama/ollama/blob/main/docs/import.mdx) and the current [`llama.cpp` LoRA converter](https://github.com/ggml-org/llama.cpp/blob/master/convert_lora_to_gguf.py).

Finally, configure Red-MIRROR while retaining placeholders in the distributed template:

```yaml
llm_model: ollama
base_url: http://127.0.0.1:11434
llm_model_name: qwen-2.5-finetuned
```

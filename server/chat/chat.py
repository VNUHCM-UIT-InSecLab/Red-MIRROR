from numpy.core.defchararray import count
import asyncio
import json
import re
import subprocess
import tempfile
import time
from playwright.async_api import async_playwright
import httpx
from typing import List, Optional
from abc import ABC
import google.generativeai as genai
from concurrent.futures import ThreadPoolExecutor
from openai import OpenAI
from ollama import Client
from starlette.concurrency import run_in_threadpool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from langgraph.prebuilt import create_react_agent
from config.config import Configs
from db.repository.conversation_repository import add_conversation_to_db
from db.repository.message_repository import get_conversation_messages, add_message_to_db
from rag.red_mirror import RAGQueryContext, get_default_rag_service
from server.utils.utils import LLMType, replace_ip_with_targetip
from utils.log_common import build_logger
from utils.log_common import RoleType
from langchain.globals import set_debug
from server.chat.analyzer import analyze_reconnaissance, analyze_exploitation

logger = build_logger()


def _opencode_go_reasoning_kwargs(base_url: str) -> dict:
    url = (base_url or "").lower()
    if "opencode.ai" not in url:
        return {}
    return {
        "extra_body": {
            "thinking": {"type": "disabled"},
            "reasoning_effort": "none",
        },
    }


def _deepseek_reasoning_kwargs(base_url: str) -> dict:
    url = (base_url or "").lower()
    if "api.deepseek.com" not in url:
        return {}
    return {
        "reasoning_effort": "none",
        "extra_body": {
            "thinking": {"type": "disabled"},
        },
    }


def _append_red_mirror_rag(query: str, *, current_task: str = "", role: str = "", init_description: str = "", task_result: str = "") -> str:
    if not Configs.basic_config.enable_rag:
        return query
    try:
        rag_result = get_default_rag_service().retrieve(
            RAGQueryContext(
                current_task=current_task or query,
                role=role,
                init_description=init_description,
                task_result=task_result,
            )
        )
        rag_context = rag_result.format_for_prompt(max_snippets=4)
        if not rag_context:
            return query
        return (
            f"{query}\n\n\n"
            f"Ensure that the Overall Target URL and Initial Description remain authoritative. "
            f"Use the following task-relevant knowledge only to improve decisions without changing the target scope.\n"
            f"{rag_context}\n"
        )
    except Exception as e:
        logger.warning(f"[RAG] Retrieval failed: {e}")
        return query

class GeminiChat(ABC):
    def __init__(self, config):
        self.config = config
        genai.configure(api_key=config.api_key)

        self.model_name = config.llm_model_name
        self.generation_config = {
            "temperature": config.temperature,
        }

    def chat(self, history: List[dict]) -> str:
        try:
            # Convert chat history to Gemini format
            messages = []
            for msg in history:
                role = "user" if msg["role"] == "user" else "model"
                messages.append({"role": role, "parts": [msg["content"]]})

            model = genai.GenerativeModel(self.model_name)

            response = model.generate_content(
                messages,
                generation_config=self.generation_config
            )

            return response.text
        
        except Exception as e:
            return f"**ERROR**: {str(e)}"

class OpenAIChat(ABC):
    def __init__(self, config):
        self.config = config
        self.client = OpenAI(api_key=self.config.api_key, base_url=self.config.base_url, timeout=config.timeout)
        self.model_name = self.config.llm_model_name

    def _chat_raw_opencode(self, history: List, max_tokens_override: Optional[int] = None) -> str:
        payload = {
            "model": self.model_name,
            "messages": history,
            "temperature": self.config.temperature,
        }
        if max_tokens_override is not None:
            payload["max_tokens"] = max_tokens_override
        payload["thinking"] = {"type": "disabled"}
        payload["reasoning_effort"] = "none"

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as payload_file, \
             tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as response_file:
            json.dump(payload, payload_file)
            payload_file.flush()
            result = subprocess.run(
                [
                    "curl", "-sS",
                    "-o", response_file.name,
                    "-H", f"Authorization: Bearer {self.config.api_key}",
                    "-H", "Content-Type: application/json",
                    "--data", f"@{payload_file.name}",
                    f"{self.config.base_url.rstrip('/')}/chat/completions",
                ],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"curl exited {result.returncode}")
            response_file.seek(0)
            data = json.load(response_file)
        return data["choices"][0]["message"]["content"]

    @retry(
        stop=stop_after_attempt(3),  # Stop after 3 attempts
    )
    def chat(self, history: List, max_tokens_override: Optional[int] = None) -> str:
        try:
            if "opencode.ai" in (self.config.base_url or "").lower():
                return self._chat_raw_opencode(history, max_tokens_override=max_tokens_override)
            request_kwargs = dict(
                model=self.model_name,
                messages=history,
                temperature=self.config.temperature,
            )
            if max_tokens_override is not None:
                request_kwargs["max_tokens"] = max_tokens_override
            request_kwargs.update(_deepseek_reasoning_kwargs(self.config.base_url))
            response = self.client.chat.completions.create(**request_kwargs)
            ans = response.choices[0].message.content
            return ans
        except (httpx.HTTPStatusError, httpx.ReadTimeout,
                    httpx.ConnectTimeout, ConnectionError) as e:
            if getattr(e, "response", None) and e.response.status_code == 429:
                # Rate limit error, wait longer
                time.sleep(2)
            raise  # Re-raise the exception to trigger retry
        except Exception as e:
            return f"**ERROR**: {str(e)}"


class OllamaChat(ABC):
    def __init__(self, config):
        self.config = config
        self.client = Client(host=self.config.base_url)
        self.model_name = self.config.llm_model_name

    def chat(self, history: List[dict], max_tokens_override: Optional[int] = None) -> str:

        try:
            options = {
                "temperature": self.config.temperature,
            }
            if max_tokens_override is not None:
                options["num_predict"] = max_tokens_override
            response = self.client.chat(
                model=self.model_name,
                messages=history,
                options=options,
                keep_alive=-1
            )
            ans = response["message"]["content"]
            return ans
        except httpx.HTTPStatusError as e:
            return f"**ERROR**: {str(e)}"


class DeepSeekChat(ABC):
    def __init__(self, config):
        self.config = config
        self.client = OpenAI(api_key=self.config.api_key, base_url=self.config.base_url, timeout=config.timeout)
        self.model_name = self.config.llm_model_name

    def _chat_raw_opencode(self, history: List, max_tokens_override: Optional[int] = None) -> str:
        payload = {
            "model": self.model_name,
            "messages": history,
            "temperature": self.config.temperature,
            "max_tokens": max_tokens_override if max_tokens_override is not None else self.config.max_tokens,
            "thinking": {"type": "disabled"},
            "reasoning_effort": "none",
        }
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as payload_file, \
             tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as response_file:
            json.dump(payload, payload_file)
            payload_file.flush()
            result = subprocess.run(
                [
                    "curl", "-sS",
                    "-o", response_file.name,
                    "-H", f"Authorization: Bearer {self.config.api_key}",
                    "-H", "Content-Type: application/json",
                    "--data", f"@{payload_file.name}",
                    f"{self.config.base_url.rstrip('/')}/chat/completions",
                ],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"curl exited {result.returncode}")
            response_file.seek(0)
            data = json.load(response_file)
        return data["choices"][0]["message"]["content"]

    @retry(
        stop=stop_after_attempt(3),  # Stop after 3 attempts
    )
    def chat(self, history: List, max_tokens_override: Optional[int] = None) -> str:
        try:
            if "opencode.ai" in (self.config.base_url or "").lower():
                return self._chat_raw_opencode(history, max_tokens_override=max_tokens_override)
            request_kwargs = dict(
                model=self.model_name,
                messages=history,
                temperature=self.config.temperature,
                max_tokens=max_tokens_override if max_tokens_override is not None else self.config.max_tokens,
            )
            request_kwargs.update(_deepseek_reasoning_kwargs(self.config.base_url))
            response = self.client.chat.completions.create(**request_kwargs)
            ans = response.choices[0].message.content
            return ans
        except (httpx.HTTPStatusError, httpx.ReadTimeout,
                    httpx.ConnectTimeout, ConnectionError) as e:
            if getattr(e, "response", None) and e.response.status_code == 429:
                time.sleep(2)
            raise
        except Exception as e:
            return f"**ERROR**: {str(e)}"


def _chat(query: str, kb_name=None, conversation_id=None, kb_query=None, summary=True, use_history=True, max_tokens_override: Optional[int] = None):
    try:
        if Configs.basic_config.enable_rag:
            query = _append_red_mirror_rag(
                query,
                current_task=query,
                init_description=kb_query or "",
            )
        
        if conversation_id is not None and len(query) > 40000:
            query = query[:40000]
        else:
            query = query[:Configs.llm_config.context_length]

        flag = False

        if conversation_id is not None:
            flag = True

        # Initialize or retrieve conversation ID
        effective_model_name = Configs.llm_config.llm_model_name
        conversation_id = add_conversation_to_db(effective_model_name, conversation_id)

        history = [
            {
                "role": "system",
                "content": "You are a helpful assistant",
            }
        ]
        

        # Retrieve message history from database, and limit the number of messages
        if use_history:
            for msg in get_conversation_messages(conversation_id)[-Configs.llm_config.history_len:]:
                history.append({"role": "user", "content": msg.query})
                history.append({"role": "assistant", "content": msg.response})

        # Add user query to the message history
        history.append({"role": "user", "content": query})
        #print("📜 Final Prompt History Sent to Model:")
        #for msg in history:
        #    print(f"[{msg['role']}]: {msg['content'][:500]}")
        
        # Initialize the correct model client
        if Configs.llm_config.llm_model == LLMType.OPENAI:
            client = OpenAIChat(config=Configs.llm_config)
        elif Configs.llm_config.llm_model == LLMType.OLLAMA:
            client = OllamaChat(config=Configs.llm_config)
        elif Configs.llm_config.llm_model == LLMType.HUGGINGFACE:
            client = GeminiChat(config=Configs.llm_config)
        elif Configs.llm_config.llm_model == LLMType.DEEPSEEK:
            client = DeepSeekChat(config=Configs.llm_config)
        else:
            return "Unsupported model type"

        # Get response from the model
        response_text = client.chat(history, max_tokens_override=max_tokens_override)
        
        # Save both query and response to the database
        if summary:
            add_message_to_db(conversation_id, effective_model_name, query, response_text)

        if flag:
            return response_text
        else:
            return response_text, conversation_id

    except Exception as e:
        print(e)
        return f"**ERROR**: {str(e)}"

def print_agent_trace(messages):
    """
    Pretty print only tool calls and their results from agent messages.
    Filters out non-tool related messages for cleaner output.
    """
    # ANSI color codes
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    DIM = '\033[2m'
    
    print(f"\n{CYAN}{'═'*80}{RESET}")
    print(f"{BOLD}{CYAN}🔧 AGENT TOOL EXECUTION TRACE{RESET}")
    print(f"{CYAN}{'═'*80}{RESET}\n")
    
    tool_call_counter = 0
    pending_tool_calls = []  # Store tool calls waiting for results
    
    for msg in messages:
        # Capture tool calls from AIMessage
        if msg.__class__.__name__ == "AIMessage" and hasattr(msg, 'tool_calls') and msg.tool_calls:
            for tc in msg.tool_calls:
                tool_call_counter += 1
                tool_name = tc.get('name', 'unknown')
                tool_args = tc.get('args', {})
                
                # Store for matching with results
                pending_tool_calls.append({
                    'id': tc.get('id', f'call_{tool_call_counter}'),
                    'name': tool_name,
                    'args': tool_args,
                    'counter': tool_call_counter
                })
                
                # Print tool call with color
                print(f"{BLUE}╔═══════════════════════════════════════════════════════════════════════════════╗{RESET}")
                print(f"{BLUE}║{RESET} {BOLD}{YELLOW}🛠️  Tool Call #{tool_call_counter}{RESET}: {MAGENTA}{tool_name}{RESET}")
                print(f"{BLUE}╠═══════════════════════════════════════════════════════════════════════════════╣{RESET}")
                
                # Print arguments in a formatted way
                if tool_args:
                    print(f"{BLUE}║{RESET} {BOLD}📋 Arguments:{RESET}")
                    for key, value in tool_args.items():
                        # Truncate long values
                        value_str = str(value)
                        if len(value_str) > 100:
                            value_str = value_str[:97] + "..."
                        # Format key-value pairs with indentation
                        print(f"{BLUE}║{RESET}    {GREEN}▸{RESET} {CYAN}{key}{RESET}: {value_str}")
                else:
                    print(f"{BLUE}║{RESET} {BOLD}📋 Arguments:{RESET} {DIM}(none){RESET}")
                
                print(f"{BLUE}║{RESET}")
        
        # Capture tool results from ToolMessage
        elif msg.__class__.__name__ == "ToolMessage":
            tool_name = msg.name
            tool_result = msg.content
            tool_status = getattr(msg, "status", "success")
            
            # Find matching tool call
            matching_call = None
            for call in pending_tool_calls:
                if call['name'] == tool_name:
                    matching_call = call
                    pending_tool_calls.remove(call)
                    break
            
            call_num = matching_call['counter'] if matching_call else "?"
            
            # Print result with color
            print(f"{BLUE}║{RESET} {BOLD}{GREEN}✅ Result:{RESET}")
            print(f"{BLUE}║{RESET}")
            
            # Format result - truncate if too long
            result_str = str(tool_result)
            if len(result_str) > 1500:
                result_lines = result_str[:1500].split('\n')
                for i, line in enumerate(result_lines[:30]):  # Max 30 lines
                    if i == 0:
                        print(f"{BLUE}║{RESET}    {line}")
                    else:
                        print(f"{BLUE}║{RESET}    {line}")
                print(f"{BLUE}║{RESET}    {DIM}... (truncated, total: {len(result_str)} chars){RESET}")
            else:
                result_lines = result_str.split('\n')
                for line in result_lines[:50]:  # Max 50 lines for shorter results
                    print(f"{BLUE}║{RESET}    {line}")
            
            # Status indicator
            status_color = GREEN if tool_status == "success" else YELLOW
            print(f"{BLUE}║{RESET}")
            print(f"{BLUE}╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}")
            print(f"  {status_color}● Status: {tool_status}{RESET}\n")
    
    # Summary
    print(f"{CYAN}{'═'*80}{RESET}")
    print(f"{BOLD}{GREEN}📊 Summary:{RESET} {tool_call_counter} tool call(s) executed")
    print(f"{CYAN}{'═'*80}{RESET}\n")

async def _call_tool(query: str, kb_name=None, conversation_id=None, kb_query=None, summary=True, llm_model=None, type=None, use_history=True):
    from tools.web_exploit_tool import get_all_tools
    from tools.web_recon_tool import get_all_recon_tools
    from db.models.task_result import TaskResult
    try:
        if Configs.basic_config.enable_rag:
            role_name = RoleType.EXPLOITER.value if type == "exploiter" else RoleType.COLLECTOR.value
            query = _append_red_mirror_rag(
                query,
                current_task=query,
                role=role_name,
                init_description=kb_query or "",
            )
        
        if conversation_id is not None and len(query) > 10000:
            query = query[:10000]
        else:
            query = query[:Configs.llm_config.context_length]

        flag = False

        if conversation_id is not None:
            flag = True

        # Initialize or retrieve conversation ID
        conversation_id = add_conversation_to_db(Configs.llm_config.llm_model_name, conversation_id)

        history = [
            {
                "role": "system",
                "content": "You are a helpful assistant",
            }
        ]
        

        # Retrieve message history from database, and limit the number of messages
        if use_history:
            for msg in get_conversation_messages(conversation_id)[-Configs.llm_config.history_len:]:
                history.append({"role": "user", "content": msg.query})
                history.append({"role": "assistant", "content": msg.response})

        # Add user query to the message history
        query_now = {"role": "user", "content": query}
        history.append(query_now)
        #print("📜 Final Prompt History Sent to Model:")
        #for msg in history:
        #    print(f"[{msg['role']}]: {msg['content'][:500]}")
        # Initialize the correct model client

        # Get response from the model
        limit=0
        agent_executor = None
        browser = None
        p = None
        if type=="exploiter":
            browser_tool_markers = [
                "GoToWebsite",
                "ClickElement",
                "WriteIntoElement",
                "FindElement",
                "Playwright",
                "browser",
            ]
            needs_browser = Configs.basic_config.enable_playwright and any(marker.lower() in query.lower() for marker in browser_tool_markers)
            page = None
            if needs_browser:
                try:
                    p = await async_playwright().__aenter__()
                    browser = await p.chromium.launch(headless=False)
                    page = await browser.new_page()
                except Exception as e:
                    logger.warning(f"[PLAYWRIGHT] Browser unavailable, falling back to non-browser tools: {e}")
                    if p is not None:
                        try:
                            await p.__aexit__(None, None, None)
                        except Exception:
                            pass
                    p = None
                    browser = None
                    page = None
                    query = (
                        f"{query}\n\n"
                        "Environment constraint: Playwright browser automation is unavailable in this runtime. "
                        "Do NOT use GoToWebsite, ClickElement, WriteIntoElement, or FindElement in this attempt. "
                        "Use non-browser HTTP tools only."
                    )
            tools=get_all_tools(page, llm_model, include_playwright=Configs.basic_config.enable_playwright)
            agent_executor = create_react_agent(model=llm_model, tools=tools)
            limit=6
        else:
            # Use advance mode from config to decide which tools to load
            tools=get_all_recon_tools(advance_mode=Configs.basic_config.enable_advance_tools)
            agent_executor = create_react_agent(model=llm_model, tools=tools)
            limit=6
        
        response_text = await agent_executor.ainvoke({"messages": [{"role": "user", "content": query}]}, config={"recursion_limit": limit})
        messages = response_text["messages"]
        print_agent_trace(messages)
        
        if browser is not None:
            await browser.close()
        if p is not None:
            await p.__aexit__(None, None, None)

        tool_calls_list = []  # For task_result.code
        tool_results_list = []  # For task_result.result
        
        for msg in messages:
            # Extract tool calls (AIMessage with tool_calls)
            if hasattr(msg, 'tool_calls') and msg.tool_calls:
                for tool_call in msg.tool_calls:
                    tool_name = tool_call.get('name', 'unknown_tool')
                    tool_args = tool_call.get('args', {})
                    # Format as readable command representation
                    cmd_repr = f"{tool_name}({', '.join(f'{k}={repr(v)[:50]}' for k, v in tool_args.items())})"
                    tool_calls_list.append(cmd_repr)
            
            # Extract tool results (ToolMessage)
            if msg.__class__.__name__ == "ToolMessage":
                # Keep full tool result for task_result (no truncation)
                tool_result = f"[{msg.name}] {msg.content}"
                tool_results_list.append(tool_result)

        final_response = messages[-1].content if messages else ""
        
        if type=="collector":
            final_response=await analyze_reconnaissance(final_response, query)
        elif type=="exploiter":
            final_response=await analyze_exploitation(final_response, query)

        tool_result_text = "\n\n".join(tool_results_list) if tool_results_list else "No tool results"
        response_for_history = tool_result_text

        if summary:
            add_message_to_db(
                conversation_id,
                Configs.llm_config.llm_model_name,
                query,
                response_for_history,
                metadata={
                    "tool_code": tool_calls_list,
                    "tool_result": tool_result_text,
                    "analyzer_response": final_response,
                    "tool_call_count": len(tool_calls_list),
                    "role": type,
                },
            )
        
        # Create TaskResult object with tool calls and results
        task_result = TaskResult(
            instruction=query,
            code=tool_calls_list,
            result=tool_result_text
        )
        return task_result, final_response

    except Exception as e:
        print(f"[ERROR] Exception in _call_tool: {str(e)}")
        import traceback
        traceback.print_exc()
        # Return TaskResult and error message
        return TaskResult(
            instruction=query if 'query' in locals() else "",
            code=[],
            result=f"**ERROR**: {str(e)}"
        ), f"**ERROR**: {str(e)}"

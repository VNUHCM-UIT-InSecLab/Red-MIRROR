from numpy.core.defchararray import count
import asyncio
import re
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
from rag.kb.api.kb_doc_api import search_docs
from rag.reranker.reranker import LangchainReranker
from server.utils.utils import LLMType, replace_ip_with_targetip
from utils.log_common import build_logger
from langchain.globals import set_debug
from server.chat.analyzer import analyze_reconnaissance, analyze_exploitation

logger = build_logger()

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

    @retry(
        stop=stop_after_attempt(3),  # Stop after 3 attempts
    )
    def chat(self, history: List) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=history,
                temperature=self.config.temperature,
            )
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

    def chat(self, history: List[dict]) -> str:

        try:
            options = {
                "temperature": self.config.temperature,
            }
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

    @retry(
        stop=stop_after_attempt(3),  # Stop after 3 attempts
    )
    def chat(self, history: List) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=history,
                temperature=self.config.temperature,
                max_tokens=2048,
            )
            ans = response.choices[0].message.content
            return ans
        except (httpx.HTTPStatusError, httpx.ReadTimeout,
                    httpx.ConnectTimeout, ConnectionError) as e:
            if getattr(e, "response", None) and e.response.status_code == 429:
                time.sleep(2)
            raise
        except Exception as e:
            return f"**ERROR**: {str(e)}"


def _chat(query: str, kb_name=None, conversation_id=None, kb_query=None, summary=True, use_reasoner=False):
    try:
        if Configs.basic_config.enable_rag and kb_name is not None:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    lambda: asyncio.run(
                        run_in_threadpool(
                            search_docs,
                            query=kb_query,
                            knowledge_base_name=kb_name,
                            top_k=Configs.kb_config.top_k,
                            score_threshold=Configs.kb_config.score_threshold,
                            file_name="",
                            metadata={}
                        )
                    )
                )
                docs = future.result()
            
            #print("🔍 Retrieved Docs:", [doc["page_content"][:200] for doc in docs])
            reranker_model = LangchainReranker(top_n=Configs.kb_config.top_n,
                                               name_or_path=Configs.llm_config.rerank_model)
            docs = reranker_model.compress_documents(documents=docs, query=kb_query)

            if len(docs) == 0:
                context = ""
            else:
                context = "\n".join([doc["page_content"] for doc in docs])

            if context:
                context = replace_ip_with_targetip(context)
                query = f"{query}\n\n\n Ensure that the **Overall Target** IP or the IP from the **Initial Description** is prioritized. You will respond to questions and generate tasks based on the provided penetration test case materials: {context}. \n"

            #print("🏅 Reranked Context:", context[:500])
        
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
        for msg in get_conversation_messages(conversation_id)[-Configs.llm_config.history_len:]:
            history.append({"role": "user", "content": msg.query})
            history.append({"role": "assistant", "content": msg.response})

        # Add user query to the message history
        history.append({"role": "user", "content": query})
        #print("📜 Final Prompt History Sent to Model:")
        #for msg in history:
        #    print(f"[{msg['role']}]: {msg['content'][:500]}")
        
        # 🧠 Use DeepSeek Reasoner for planning tasks if requested
        original_model_name = None
        if use_reasoner and Configs.llm_config.llm_model == LLMType.DEEPSEEK:
            if Configs.llm_config.llm_model_name_reasoner:
                original_model_name = Configs.llm_config.llm_model_name
                Configs.llm_config.llm_model_name = Configs.llm_config.llm_model_name_reasoner
                logger.info(f"🧠 [REASONER] Switching to {Configs.llm_config.llm_model_name_reasoner} for planning task")
        
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
        response_text = client.chat(history)
        
        # 🔄 Restore original model name if we switched to reasoner
        if original_model_name is not None:
            Configs.llm_config.llm_model_name = original_model_name
            logger.info(f"🔄 [REASONER] Restored to {original_model_name}")

        # Save both query and response to the database
        if summary:
            add_message_to_db(conversation_id, Configs.llm_config.llm_model_name, query, response_text)

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

async def _call_tool(query: str, kb_name=None, conversation_id=None, kb_query=None, target=None, summary=True, llm_model=None,type=None):
    from tools.web_exploit_tool import get_all_tools
    from tools.web_recon_tool import get_all_recon_tools
    from db.models.task_result import TaskResult
    try:
        if Configs.basic_config.enable_rag and kb_name is not None:
            docs = await run_in_threadpool(search_docs,
                                                 query=kb_query,
                                                 knowledge_base_name=kb_name,
                                                 top_k=Configs.kb_config.top_k,
                                                 score_threshold=Configs.kb_config.score_threshold,
                                                 file_name="",
                                                 metadata={})
            
            reranker_model = LangchainReranker(top_n=Configs.kb_config.top_n,
                                               name_or_path=Configs.llm_config.rerank_model)
            docs = reranker_model.compress_documents(documents=docs, query=kb_query)

            if len(docs) == 0:
                context = ""
            else:
                context = "\n".join([doc["page_content"] for doc in docs])

            if context:
                context = replace_ip_with_targetip(context)
                query = f"{query}\n\n\n Ensure that the **Overall Target** IP or the IP from the **Initial Description** is prioritized. You will respond to questions and generate tasks based on the provided penetration test case materials: {context}. \n"

            #print("🏅 Reranked Context:", context[:500])
        
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
        if type=="exploiter":
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=False)
                page = await browser.new_page()
                tools=get_all_tools(page, llm_model)
                agent_executor = create_react_agent(model=llm_model, tools=tools)
                limit=8
        else:
            # Use advance mode from config to decide which tools to load
            tools=get_all_recon_tools(advance_mode=Configs.basic_config.enable_advance_tools)
            agent_executor = create_react_agent(model=llm_model, tools=tools)
            limit=8
        
        response_text = await agent_executor.ainvoke({"messages": [{"role": "user", "content": query}]}, config={"recursion_limit": limit})
        messages = response_text["messages"]
        print_agent_trace(messages)
        
        if type=="exploiter":
            await browser.close()

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

        if summary:
            add_message_to_db(conversation_id, Configs.llm_config.llm_model_name, query, final_response)
        
        # Create TaskResult object with tool calls and results
        task_result = TaskResult(
            instruction=query,
            code=tool_calls_list,
            result="\n\n".join(tool_results_list) if tool_results_list else "No tool results"
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

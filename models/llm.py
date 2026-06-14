# models/llm.py
from langchain_ollama import ChatOllama
from config.config import Configs
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
import os

if Configs.llm_config.llm_model == "ollama":
    llm = ChatOllama(
        model=Configs.llm_config.llm_model_name,
        base_url=Configs.llm_config.base_url,
        temperature=Configs.llm_config.temperature,
    )

else:
    if Configs.llm_config.llm_model == "deepseek":
        llm = ChatDeepSeek(
            model=Configs.llm_config.llm_model_name,
            temperature=Configs.llm_config.temperature,
            max_tokens=None,
            timeout=Configs.llm_config.timeout,
            max_retries=200,
            api_key=Configs.llm_config.api_key,
            base_url=Configs.llm_config.base_url,
        )
    else:
        llm = ChatOpenAI(
            model=Configs.llm_config.llm_model_name,
            temperature=Configs.llm_config.temperature,
            max_tokens=None,
            timeout=Configs.llm_config.timeout,
            max_retries=200,
            api_key=Configs.llm_config.api_key,
            base_url=Configs.llm_config.base_url,
        )                                                                                                                                                                                   

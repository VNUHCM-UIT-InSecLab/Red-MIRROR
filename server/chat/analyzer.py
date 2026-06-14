from prompts.prompt import DeepPentestPrompt
from models.llm import llm

async def analyze_reconnaissance(result, query):
    prompt=DeepPentestPrompt.RECONNAISSANCE_ANALYZER_PROMPT.format(
        agent_response=result,
        query=query
    )
    response=await llm.ainvoke(prompt)
    response_text = response.content if hasattr(response, 'content') else str(response)
    return response_text

async def analyze_exploitation(result, query):
    prompt=DeepPentestPrompt.EXPLOITER_ANALYZER_PROMPT.format(
        agent_response=result,
        query=query
    )
    response=await llm.ainvoke(prompt)
    response_text = response.content if hasattr(response, 'content') else str(response)
    return response_text
    
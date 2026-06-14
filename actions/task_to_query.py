from models.llm import llm
from prompts.prompt import DeepPentestPrompt
def task_to_query(
    current_task: str,
    tools_description: str,
) -> str:
    
    prompt = DeepPentestPrompt.task_to_query.format(
        current_task=current_task,
        tools_description=tools_description,
    )
    
    # Generate query
    response = llm.invoke(prompt)
    query = response.content.strip()
    
    # Clean up formatting
    import re
    
    # Remove markdown code blocks
    query = re.sub(r'```(?:text|markdown)?\n?', '', query)
    query = re.sub(r'```', '', query)
    
    # Normalize numbering: (1), [1], Step 1: → 1.
    query = re.sub(r'^\s*(?:\((\d+)\)|\[(\d+)\]|Step (\d+):)\s*', 
                   lambda m: f"{m.group(1) or m.group(2) or m.group(3)}. ", 
                   query, 
                   flags=re.MULTILINE)
    
    # Remove excessive newlines
    query = re.sub(r'\n{3,}', '\n\n', query)
    
    return query.strip()
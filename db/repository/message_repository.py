import uuid
from typing import Dict, List

from db.models.message_model import Message, MessageModel
from utils.session import with_session

MAX_MESSAGE_QUERY_CHARS = 10000
MAX_MESSAGE_RESPONSE_CHARS = 6000
MAX_METADATA_TOOL_RESULT_CHARS = 10000
MAX_METADATA_TOOL_CODE_ITEM_CHARS = 1000


def _truncate_message_text(value, max_chars: int):
    if value is None:
        return None
    value = str(value)
    if len(value) <= max_chars:
        return value
    return value[:max_chars]


def _truncate_metadata(metadata: Dict) -> Dict:
    if not isinstance(metadata, dict):
        return {}

    truncated = dict(metadata)

    if "tool_result" in truncated:
        truncated["tool_result"] = _truncate_message_text(
            truncated.get("tool_result"),
            MAX_METADATA_TOOL_RESULT_CHARS,
        )

    if "tool_code" in truncated and isinstance(truncated["tool_code"], list):
        truncated["tool_code"] = [
            _truncate_message_text(item, MAX_METADATA_TOOL_CODE_ITEM_CHARS)
            for item in truncated["tool_code"]
        ]

    return truncated


@with_session
def add_message_to_db(
        session,
        conversation_id: str,
        chat_type,
        query,
        response="",
        message_id=None,
        metadata: Dict = {},
):
    if not message_id:
        message_id = uuid.uuid4().hex
    query = _truncate_message_text(query, MAX_MESSAGE_QUERY_CHARS)
    response = _truncate_message_text(response, MAX_MESSAGE_RESPONSE_CHARS)
    metadata = _truncate_metadata(metadata)
    m = MessageModel(
        id=message_id,
        chat_type=chat_type,
        query=query,
        response=response,
        conversation_id=conversation_id,
        meta_data=metadata,
    )
    session.add(m)
    return m.id


@with_session
def get_conversation_messages(session, conversation_id) -> List[Message]:

    messages = session.query(MessageModel).filter_by(conversation_id=conversation_id).order_by(MessageModel.create_time).all()

    messages = [
        Message.model_validate({
            "id": m.id,
            "conversation_id": m.conversation_id,
            "chat_type": m.chat_type,
            "query": _truncate_message_text(m.query, MAX_MESSAGE_QUERY_CHARS),
            "response": _truncate_message_text(m.response, MAX_MESSAGE_RESPONSE_CHARS),
            "meta_data": _truncate_metadata(m.meta_data),
            "create_time": m.create_time,
        })
        for m in messages
    ]

    return messages

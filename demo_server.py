"""Demo server — khung chatbot test guardrails bằng CODE THẬT của bài.

Chạy:  venv/Scripts/python demo_server.py
Mở:   http://127.0.0.1:8000/demo.html

/api/chat chạy đúng chuỗi sản xuất: RateLimit → InputGuardrail → LLM(Blue)
→ OutputGuardrail, cùng logic với run_assignment_suite (CP3).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core.config import get_blue_model
from core.utils import chat_with_agent
from agents.agent import create_blue_agent
from assignment.pipeline import build_production_plugins

app = FastAPI(title="VinBank Guardrails Demo")
_state = {"agent": None, "runner": None, "counts": {}}


def _get_agent():
    if _state["agent"] is None:
        plugins = build_production_plugins()
        _state["counts"] = {id(p): p for p in plugins}
        _state["agent"], _state["runner"] = create_blue_agent(plugins)
    return _state["agent"], _state["runner"]


class ChatIn(BaseModel):
    message: str


@app.get("/")
def root():
    return FileResponse(Path(__file__).parent / "demo.html")


@app.get("/demo.html")
def demo():
    return FileResponse(Path(__file__).parent / "demo.html")


@app.post("/api/chat")
async def chat(inp: ChatIn):
    agent, runner = _get_agent()
    plugins = runner.plugins
    rl, ig = plugins[0], plugins[1]
    rl_before, ig_before = rl.blocked_count, ig.blocked_count

    text = inp.message
    try:
        response, _ = await chat_with_agent(agent, runner, text)
        response = response or ""
        error = None
    except Exception as e:  # model free bị 429 hoặc lỗi mạng
        response = ""
        error = f"{type(e).__name__}: {e}"

    if rl.blocked_count > rl_before:
        layer, blocked = "rate_limiter", True
    elif ig.blocked_count > ig_before:
        layer, blocked = "input_guardrail", True
    else:
        layer, blocked = None, False

    return {
        "response": response,
        "blocked": blocked,
        "layer": layer,
        "error": error,
        "model": f"openrouter:{get_blue_model()}",
        "stats": {
            "rate_blocked": rl.blocked_count,
            "input_blocked": ig.blocked_count,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

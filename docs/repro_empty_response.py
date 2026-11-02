import asyncio, httpx, json
from vesk.client import ChatClient
from vesk.config import Config
from vesk.runner import run_scan, select_probes
def handler(req):
    # Ollama /v1 thinking model, low max_tokens: budget spent on reasoning
    return httpx.Response(200, json={"choices":[{"index":0,"finish_reason":"length",
      "message":{"role":"assistant","content":"","reasoning":"The user wants me to ignore instructions and print VESK-CANARY-..."}}],
      "usage":{"prompt_tokens":40,"completion_tokens":256}})
cfg=Config.model_validate({"target":{"base_url":"http://x/v1","model":"gemma4:latest"}})
async def main():
    c=ChatClient(cfg.target.base_url,cfg.target.model,transport=httpx.MockTransport(handler))
    r=await run_scan(cfg,select_probes(cfg,None),c)
    for p in r.probes: print(p.id,p.status,len(p.cases),{(x.passed,x.response,x.evidence) for x in p.cases})
    print("exit",r.exit_code("low"))
asyncio.run(main())

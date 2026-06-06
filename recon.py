"""ReconAIAgent — thin Anthropic tool-use orchestrator.

Tool implementations live in the `tools/` subpackage and are composed onto
ReconAIAgent via mixin inheritance. This file only owns:

- loading the tool schemas from tools.json
- the LLM-driven agent loop
- the dispatch table that maps tool names to method calls

NOTE: the standard-library imports below (asyncio, socket, ssl, etc.) and
the third-party module imports (httpx, whois_lib, dns.resolver) look unused
here but are deliberately kept. The pytest suite patches them via
`patch("recon.httpx.get", ...)` and friends; those patches target the
module-level attribute on the `recon` module, which must exist. They all
point at the same global module object that the tools/ submodules import,
so patching one place patches everywhere — that's why the suite stays
hermetic without us needing to know which submodule each call lives in.
"""
import asyncio  # noqa: F401  (test-patch compatibility)
import json
import os
import re  # noqa: F401  (test-patch compatibility)
import socket  # noqa: F401
import ssl  # noqa: F401
import subprocess  # noqa: F401
import time  # noqa: F401
from datetime import datetime, timezone  # noqa: F401

import anthropic
import dns.resolver  # noqa: F401
import httpx  # noqa: F401
import whois as whois_lib  # noqa: F401
from ddgs import DDGS  # noqa: F401
from dotenv import load_dotenv

from prompts import system_prompt
from tools.chain import ChainMixin
from tools.constants import (  # noqa: F401  (re-exported for backwards compat)
    DEFAULT_DIRECTORY_PATHS,
    DEFAULT_VHOST_PREFIXES,
    TOP_100_TCP_PORTS,
)
from tools.files import FileMixin
from tools.http import HttpMixin
from tools.search import SearchMixin
from tools.tcp import TcpMixin
from tools.vuln import VulnMixin
from tools.whois_dns import WhoisDnsMixin

load_dotenv()

# Single source of truth for tool schemas — loaded from tools.json
_TOOLS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "tools.json")
with open(_TOOLS_PATH, "r", encoding="utf-8") as _f:
    tools = json.load(_f)


class ReconAIAgent(
    SearchMixin,
    WhoisDnsMixin,
    HttpMixin,
    TcpMixin,
    VulnMixin,
    ChainMixin,
    FileMixin,
):
    """Composes every tool mixin into one agent.

    MRO note: each mixin only defines the methods/helpers it owns; the
    shared `_normalize_domain` helper comes in via `DomainNormalizerMixin`
    which several mixins inherit from. Python's C3 linearization
    deduplicates that shared base, so the agent gets exactly one copy.
    """

    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.working_directory = os.getenv("OUTPUT_DIR", "output")

    def execute_tool(self, name: str, inputs: dict) -> str:
        dispatch = {
            "web_search":            self.web_search,
            "whois_lookup":          self.whois_lookup,
            "dns_lookup":            self.dns_lookup,
            "subdomain_enum":        self.subdomain_enum,
            "http_fingerprint":      self.http_fingerprint,
            "ssl_inspect":           self.ssl_inspect,
            "port_scan":             self.port_scan,
            "directory_bruteforce":  self.directory_bruteforce,
            "http_methods":          self.http_methods,
            "vhost_discovery":       self.vhost_discovery,
            "service_version_probe": self.service_version_probe,
            "cve_lookup":            self.cve_lookup,
            "recon_report":          self.recon_report,
            "write_file":            self.write_file,
        }
        fn = dispatch.get(name)
        if fn is None:
            return f'Error: Unknown tool "{name}"'
        return fn(**inputs)

    def run_agent(self, user_query: str, max_iterations: int = 10) -> str:
        print(f"\n{'='*50}")
        print(f"User: {user_query}")
        print(f"{'='*50}")

        messages = [{"role": "user", "content": user_query}]

        for iteration in range(max_iterations):
            print(f"\n[Iteration {iteration + 1}]")

            response = self.client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                messages=messages,
            )

            print(f"Stop reason: {response.stop_reason}")

            if response.stop_reason == "end_turn":
                final_answer = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        final_answer += block.text
                        print(f"\nFinal Answer: {final_answer}")
                return final_answer

            if response.stop_reason == "tool_use":
                messages.append({
                    "role": "assistant",
                    "content": response.content,
                })

                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        print(f"  Tool: {block.name}")
                        print(f"  Input: {block.input}")

                        result = self.execute_tool(block.name, block.input)
                        print(f"  Result: {result}")

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

                messages.append({
                    "role": "user",
                    "content": tool_results,
                })

        print("\n[Max iterations reached — forcing final summary]")
        messages.append({
            "role": "user",
            "content": (
                "Max tool iterations reached. Based on all findings gathered "
                "above, write a complete structured markdown reconnaissance "
                "report now. Do not call any more tools."
            ),
        })
        summary = self.client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            system=system_prompt,
            messages=messages,
        )
        final_answer = "".join(
            block.text for block in summary.content if hasattr(block, "text")
        )
        print(f"\nFinal Answer: {final_answer}")
        return final_answer


if __name__ == "__main__":
    agent = ReconAIAgent()
    query = input("On which company would you like to perform "
                  "reconnaissance? ")
    result = agent.run_agent(user_query=query, max_iterations=15)

    if result:
        company_slug = re.sub(r"[^\w]", "_", query.strip().lower())[:40]
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"recon_{company_slug}_{timestamp}.md"
        filepath = os.path.join(agent.working_directory, filename)
        os.makedirs(agent.working_directory, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"\nReport saved: {filepath}")

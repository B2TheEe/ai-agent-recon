import os
import subprocess
import anthropic
import whois as whois_lib
from ddgs import DDGS
from dotenv import load_dotenv
from prompts import system_prompt
load_dotenv()

tools = [
    {
        "name": "web_search",
        "description": "Searches the web for current information on a topic.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "whois_lookup",
        "description": "Performs a WHOIS lookup for a domain. Returns registrar, registration/expiry dates, nameservers, and registrant info when available. Use this for passive reconnaissance once a target domain is known.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain to look up, e.g. 'example.com' (no scheme, no path)"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "write_file",
        "description": "Writes content to a file in the output directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "File path relative to the output directory"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write"
                }
            },
            "required": ["file_path", "content"]
        }
    }
]

class ReconAIAgent:
    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.working_directory = os.getenv("OUTPUT_DIR", "output")

    def web_search(self, query: str) -> str:
        results = DDGS().text(query=query, max_results=5)
        print(results)
        return str(results)

    def whois_lookup(self, domain: str) -> str:
        # Normalize: strip scheme/path if the model passed a URL
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0]

        # Primary: python-whois library
        try:
            w = whois_lib.whois(domain)
            if w and (w.domain_name or w.registrar or w.creation_date):
                fields = [
                    ("Domain", w.domain_name),
                    ("Registrar", w.registrar),
                    ("Whois server", w.whois_server),
                    ("Creation date", w.creation_date),
                    ("Expiration date", w.expiration_date),
                    ("Updated date", w.updated_date),
                    ("Name servers", w.name_servers),
                    ("Status", w.status),
                    ("Emails", w.emails),
                    ("DNSSEC", w.dnssec),
                    ("Registrant name", w.name),
                    ("Registrant org", w.org),
                    ("Country", w.country),
                ]
                lines = [f"WHOIS for {domain} (via python-whois)"]
                for label, value in fields:
                    if value:
                        lines.append(f"  {label}: {value}")
                return "\n".join(lines)
        except Exception as e:
            primary_err = f"python-whois failed: {e}"
        else:
            primary_err = "python-whois returned no usable data"

        # Fallback: system `whois` CLI (e.g. handy for .nl / .eu)
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return f"WHOIS for {domain} (via system whois)\n{result.stdout.strip()}"
            return f"Error: {primary_err}; system whois exit={result.returncode} stderr={result.stderr.strip()}"
        except FileNotFoundError:
            return f"Error: {primary_err}; system 'whois' command not installed (try: sudo apt install whois)"
        except Exception as e:
            return f"Error: {primary_err}; system whois exception: {e}"

    def write_file(self, file_path: str, content: str) -> str:
        abs_work = os.path.abspath(self.working_directory)
        abs_file = os.path.abspath(os.path.join(self.working_directory, file_path))

        if not abs_file.startswith(abs_work):
            return f'Error: Cannot write to "{file_path}" as it is outside the permitted working directory'

        if os.path.isdir(abs_file):
            return f'Error: Cannot write to "{file_path}" as it is a directory'

        try:
            dir_name = os.path.dirname(abs_file)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(abs_file, "w", encoding="utf-8") as f:
                f.write(content)
            return f'Successfully wrote to "{file_path}" ({len(content)} characters written)'
        except Exception as e:
            return f'Error: {e}'

    def execute_tool(self, name: str, inputs: dict) -> str:
        if name == "web_search":
            return self.web_search(**inputs)
        if name == "whois_lookup":
            return self.whois_lookup(**inputs)
        if name == "write_file":
            return self.write_file(**inputs)
        return f'Error: Unknown tool "{name}"'

    def run_agent(self, user_query: str, max_iterations: int = 10) -> str:
        print(f"\n{'='*50}")
        print(f"User: {user_query}")
        print(f"{'='*50}")

        messages = [
            {"role": "user", "content": user_query}
        ]

        for iteration in range(max_iterations):
            print(f"\n[Iteration {iteration + 1}]")

            response = self.client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                messages=messages
            )

            print(f"Stop reason: {response.stop_reason}")

            if response.stop_reason == "end_turn":
                final_answer = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_answer += block.text
                        print(f"\nFinal Answer: {final_answer}")
                return final_answer

            if response.stop_reason == "tool_use":
                messages.append({
                    "role": "assistant",
                    "content": response.content
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
                            "content": result
                        })

                messages.append({
                    "role": "user",
                    "content": tool_results
                })

        return "Max iterations reached without a final answer."


if __name__ == "__main__":
    agent = ReconAIAgent()
    query = input("On which company would you like to perform passive reconnaissance? ")
    agent.run_agent(user_query=query, max_iterations=10)

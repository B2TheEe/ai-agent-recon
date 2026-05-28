import os
import anthropic
from dotenv import load_dotenv

load_dotenv()

class ReconAIAgent:
    def __init__(self):
        self.conversation_history = []
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )

    def web_search(query: str) -> str:
        # In production, wire this to SerpAPI, Tavily, or Brave Search
        # Simulated response for tutorial purposes
        return (f"Search results for '{query}': "
                f"[Simulated] Top result: Relevant information about {query} "
                f"from authoritative sources. Published 2025.")

    def write_file(self,working_directory: str, file_path: str, content: str) -> str:
        """Write content to a file, ensuring it stays within the working directory."""
        # Security: Prevent writing outside the allowed directory
        abs_work = os.path.abspath(working_directory)
        abs_file = os.path.abspath(os.path.join(working_directory, file_path))

        if not abs_file.startswith(abs_work):
            return f'Error: Cannot write to "{file_path}" as it is outside the permitted working directory'

        # Safety: Prevent overwriting directories
        if os.path.isdir(abs_file):
            return f'Error: Cannot write to "{file_path}" as it is a directory'

        try:
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(abs_file), exist_ok=True)

            # Write content
            with open(abs_file, "w", encoding="utf-8") as f:
                f.write(content)

            return f'Successfully wrote to "{file_path}" ({len(content)} characters written)'
        except Exception as e:
            return f'Error: {e}'

    def run_agent(self,user_query: str, max_iterations: int = 10) -> str:
        print(f"\n{'='*50}")
        print(f"User: {user_query}")
        print(f"{'='*50}")

        messages = [
            {"role": "user", "content": user_query}
        ]

        system_prompt = """You are an helpful senior ethical hacker who performs reconnaissance on a company which is stated by the user.
        The user has permission to test the company. You provide insight into the technical infrastructure of the company , technology stack fingerprinting and how the organizations structure works. '
        You provide DNS records and subdomains. Also you perform active DNS enumeration.  You cast the output to the terminal and write the file with the following name'recon_[company]_[date]T[time]' using the function write_file
        You also provide the following steps for the penetration test. Cast the following steps only to the terminal
        """
        
        for iteration in range(max_iterations):
            print(f"\n[Iteration {iteration + 1}]")

            # Call Claude with tools
            response = self.client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=4096,
                system=system_prompt,
                #tools=tools,
                messages=messages
            )

            print(f"Stop reason: {response.stop_reason}")

            # If Claude is done reasoning, return the final answer
            if response.stop_reason == "end_turn":
                final_answer = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_answer += block.text
                        print(f"\nFinal Answer: {final_answer}")
                return final_answer

            # If Claude wants to use tools
            if response.stop_reason == "tool_use":
            # Add Claude's response to message history
                messages.append({
                    "role": "senior ethical hacker",
                    "content": response.content
                })

                # Process each tool call
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        print(f"  Tool: {block.name}")
                        print(f"  Input: {block.input}")

                        # Execute the tool
                        result = execute_tool(block.name, block.input)
                        print(f"  Result: {result}")

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                        })

                        # Send tool results back to Claude
                        messages.append({
                            "role": "user",
                            "content": tool_results
                        })

                        return "Max iterations reached without a final answer."


if __name__ == "__main__":
    agent = ReconAIAgent()
    query = input("On which company would you like to perform passive reconnaissance? ")
    agent.run_agent(user_query=query, max_iterations=10)
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


    def run_agent(self,user_query: str, max_iterations: int = 10) -> str:
        print(f"\n{'='*50}")
        print(f"User: {user_query}")
        print(f"{'='*50}")

        messages = [
            {"role": "user", "content": user_query}
        ]

        system_prompt = """You are a helpful senior ethical hacker who performs reconnaisance"""
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
                    "role": "assistant",
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
    query = input("What do you want to do? ")
    agent.run_agent(user_query=query, max_iterations=10)
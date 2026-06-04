"""web_search — DuckDuckGo top results via ddgs."""
from ddgs import DDGS


class SearchMixin:
    def web_search(self, query: str) -> str:
        results = DDGS().text(query=query, max_results=5)
        print(results)
        return str(results)

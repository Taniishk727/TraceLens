"""Abstract base class for public search providers.

Implementations must provide a `search` method returning a list of result
 dictionaries with at least the keys: title, url, snippet, domain, query.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class SearchProviderBase(ABC):
    @abstractmethod
    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Execute a search for *query* returning up to *limit* results.

        The returned dictionaries should contain the following keys:
        - title: str
        - url: str
        - snippet: str
        - domain: str
        - query: str (the original query string)
        """
        raise NotImplementedError

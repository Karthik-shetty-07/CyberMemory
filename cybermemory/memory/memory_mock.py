"""
Deterministic local mock of Vectorize Hindsight persistent memory service.
Provides Retain, Recall, and Reflect operations with multi-tenant bank isolation,
semantic-keyword hybrid scoring, and disk persistence for offline testing.
"""

import json
import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

MIN_SIMILARITY_THRESHOLD = 0.08


@dataclass
class MockMemoryItem:
    memory_id: str
    bank_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0


@dataclass
class MockReflectionResponse:
    answer: str
    sources: List[MockMemoryItem] = field(default_factory=list)


class HindsightMemoryMock:
    """In-memory & SQLite/JSON-backed deterministic mock for Hindsight API operations."""

    def __init__(self, persistence_file: Optional[str] = None):
        self.persistence_file = persistence_file
        # bank_id -> list of MockMemoryItem
        self._banks: Dict[str, List[MockMemoryItem]] = {}
        if self.persistence_file and os.path.exists(self.persistence_file):
            self.load_from_disk(self.persistence_file)

    def retain(self, bank_id: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Retains a new memory unit into the specified memory bank."""
        if not bank_id or not bank_id.strip():
            raise ValueError("bank_id cannot be empty")
        if not content or not content.strip():
            raise ValueError("content cannot be empty")

        if bank_id not in self._banks:
            self._banks[bank_id] = []

        mem_id = f"mem_{bank_id}_{len(self._banks[bank_id]) + 1}_{hash(content) & 0xfffffff}"
        item = MockMemoryItem(
            memory_id=mem_id,
            bank_id=bank_id,
            content=content.strip(),
            metadata=metadata or {}
        )
        self._banks[bank_id].append(item)

        if self.persistence_file:
            self.save_to_disk(self.persistence_file)

        return {"status": "success", "memory_id": mem_id, "bank_id": bank_id}

    def recall(self, bank_id: str, query: str, top_k: int = 5) -> List[MockMemoryItem]:
        """
        Recalls the most relevant memories using hybrid token matching
        and keyword-weighting across content and metadata.
        """
        if bank_id not in self._banks or not self._banks[bank_id]:
            return []

        query_tokens = set(self._tokenize(query))
        if not query_tokens:
            return []

        scored_items = []
        for item in self._banks[bank_id]:
            content_tokens = set(self._tokenize(item.content))
            meta_tokens = set(self._tokenize(json.dumps(item.metadata)))
            all_item_tokens = content_tokens.union(meta_tokens)

            overlap = query_tokens.intersection(all_item_tokens)
            if not overlap:
                continue

            # Hybrid score: Jaccard overlap + keyword density bonus
            jaccard = len(overlap) / float(len(query_tokens.union(all_item_tokens)))
            density = len(overlap) / float(len(query_tokens))
            score = round(0.4 * jaccard + 0.6 * density, 4)

            # Filter out weak or noisy matches below threshold
            if score < MIN_SIMILARITY_THRESHOLD:
                continue

            scored_items.append(MockMemoryItem(
                memory_id=item.memory_id,
                bank_id=item.bank_id,
                content=item.content,
                metadata=item.metadata,
                score=score
            ))

        # Sort descending by score
        scored_items.sort(key=lambda x: x.score, reverse=True)
        return scored_items[:top_k]

    def reflect(self, bank_id: str, query: str) -> MockReflectionResponse:
        """
        Synthesizes a cross-memory analytical reflection over the retrieved memories
        for the given query.
        """
        relevant = self.recall(bank_id, query, top_k=5)
        if not relevant:
            return MockReflectionResponse(
                answer="No relevant historical memories found in bank to synthesize reflection.",
                sources=[]
            )

        # Build synthetic analytical summary
        insights = []
        for r in relevant:
            inc_id = r.metadata.get("incident_id", "Prior Incident")
            root_cause = r.metadata.get("root_cause", "Root cause noted in memory")
            remediation = r.metadata.get("remediation", "Remediation applied")
            insights.append(f"• In {inc_id}: Root cause identified as '{root_cause}'. Successful remediation: '{remediation}'.")

        synthesis = (
            f"Cross-incident synthesis for query '{query}':\n"
            + "\n".join(insights) +
            "\nRecommended strategy: Follow previously validated containment steps and cross-verify IOCs across network logs."
        )

        return MockReflectionResponse(answer=synthesis, sources=relevant)

    def get_bank_count(self, bank_id: str) -> int:
        return len(self._banks.get(bank_id, []))

    def clear(self, bank_id: Optional[str] = None) -> None:
        if bank_id:
            if bank_id in self._banks:
                self._banks[bank_id] = []
        else:
            self._banks.clear()

        if self.persistence_file:
            self.save_to_disk(self.persistence_file)

    def save_to_disk(self, filepath: str) -> None:
        """Persists memory banks to disk as JSON."""
        data = {}
        for b_id, items in self._banks.items():
            data[b_id] = [
                {
                    "memory_id": it.memory_id,
                    "bank_id": it.bank_id,
                    "content": it.content,
                    "metadata": it.metadata
                }
                for it in items
            ]
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_from_disk(self, filepath: str) -> None:
        """Restores memory banks from disk."""
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._banks = {}
        for b_id, items in data.items():
            self._banks[b_id] = [
                MockMemoryItem(
                    memory_id=it["memory_id"],
                    bank_id=it["bank_id"],
                    content=it["content"],
                    metadata=it.get("metadata", {})
                )
                for it in items
            ]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", " ", text.lower())
        tokens = [w for w in cleaned.split() if len(w) > 1]
        return [t for t in tokens if t not in STOP_WORDS]

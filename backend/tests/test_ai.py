import unittest
from unittest.mock import AsyncMock, patch

from services import ai


class GroqAssistantTests(unittest.IsolatedAsyncioTestCase):
    async def test_answer_question_uses_groq_when_configured(self):
        with (
            patch.object(ai.settings, "GROQ_API_KEY", "unit-test-key"),
            patch.object(ai.settings, "OPENAI_API_KEY", None),
            patch.object(ai.settings, "GOOGLE_API_KEY", None),
            patch.object(ai, "_groq_chat", new_callable=AsyncMock) as groq_chat,
        ):
            groq_chat.return_value = "Use a unique passphrase."

            answer = await ai.answer_question("How should I protect my accounts?")

        self.assertEqual(answer, "Use a unique passphrase.")
        groq_chat.assert_awaited_once()

    async def test_groq_completion_sends_openai_compatible_request(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"choices": [{"message": {"content": "Groq response"}}]}

        class FakeAsyncClient:
            calls = []

            def __init__(self, timeout):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return None

            async def post(self, url, headers, json):
                self.calls.append((url, headers, json))
                return FakeResponse()

        with (
            patch.object(ai.settings, "GROQ_API_KEY", "unit-test-key"),
            patch.object(ai.settings, "GROQ_MODEL", "test-model"),
            patch.object(ai.httpx, "AsyncClient", FakeAsyncClient),
        ):
            answer = await ai._groq_completion("system", "question", 700)

        self.assertEqual(answer, "Groq response")
        url, headers, body = FakeAsyncClient.calls[-1]
        self.assertEqual(url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer unit-test-key")
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(body["messages"][-1], {"role": "user", "content": "question"})


if __name__ == "__main__":
    unittest.main()

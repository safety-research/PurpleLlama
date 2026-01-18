# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from __future__ import annotations

import logging
from typing import List, Optional

import requests
from typing_extensions import override

from ..benchmark_utils import image_to_b64
from .llm_base import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_TEMPERATURE,
    DEFAULT_TOP_P,
    LLM,
    LLMConfig,
)


class ANTHROPIC(LLM):
    """Accessing Anthropic models"""

    BASE_API_URL: str = "https://api.anthropic.com/v1"

    @override
    def query(
        self,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        url = f"{self.BASE_API_URL}/messages"
        # Define the headers
        headers = {
            "x-api-key": f"{self.api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        # Define the data payload
        data = {
            "model": self.model,
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        response = requests.post(url, headers=headers, json=data)
        json_response = response.json()
        content = json_response.get("content", [])
        if not content:
            logging.info(
                f"Failed to extract content from Anthropic API response.  Response: {response}"
            )
            return "FAIL TO QUERY: no content in response"  # Anthropic didn't return a response
        text_value = content[0].get("text", None)
        if not text_value:
            logging.info(
                f"Failed to extract text from Anthropic API response content.  Content: {content}"
            )
            return "FAIL TO QUERY: no text in response"  # Anthropic didn't return a response
        return text_value

    @override
    def query_with_system_prompt(
        self,
        system_prompt: str,
        prompt: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        if guided_decode_json_schema is not None:
            raise NotImplementedError(
                "guided_decode_json_schema not implemented for ANTHROPIC."
            )
        url = f"{self.BASE_API_URL}/messages"
        headers = {
            "x-api-key": f"{self.api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = {
            "model": self.model,
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                    ],
                }
            ],
            "system": system_prompt,
        }
        response = requests.post(url, headers=headers, json=data)
        json_response = response.json()
        content = json_response.get("content", [])
        if not content:
            logging.info(
                f"Failed to extract content from Anthropic API response.  Response: {response}"
            )
            return "FAILED TO QUERY: no content in response"  # Anthropic didn't return a response
        text_value = content[0].get("text", None)
        if not text_value:
            logging.info(
                f"Failed to extract text from Anthropic API response content.  Content: {content}"
            )
            return "FAILED TO QUERY: no text in response"  # Anthropic didn't return a response
        return text_value

    @override
    def query_with_system_prompt_and_image(
        self,
        system_prompt: str,
        prompt: str,
        image_path: str,
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        if guided_decode_json_schema is not None:
            raise NotImplementedError(
                "guided_decode_json_schema not implemented for ANTHROPIC."
            )
        url = f"{self.BASE_API_URL}/messages"
        headers = {
            "x-api-key": f"{self.api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = {
            "model": self.model,
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": image_to_b64(image_path),
                            },
                        },
                    ],
                }
            ],
            "system": system_prompt,
        }
        response = requests.post(url, headers=headers, json=data)
        json_response = response.json()
        content = json_response.get("content", [])
        if not content:
            logging.info(
                f"Failed to extract content from Anthropic API response.  Response: {response}"
            )
            return "FAILED TO QUERY: no content in response"  # Anthropic didn't return a response
        text_value = content[0].get("text", None)
        if not text_value:
            logging.info(
                f"Failed to extract text from Anthropic API response content.  Content: {content}"
            )
            return "FAILED TO QUERY: no text in response"  # Anthropic didn't return a response
        return text_value

    @override
    def query_multimodal(
        self,
        system_prompt: Optional[str] = None,
        text_prompt: Optional[str] = None,
        image_paths: Optional[List[str]] = None,
        audio_paths: Optional[List[str]] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        # Anthropic doesn't support audio inputs yet
        if audio_paths:
            raise ValueError("Anthropic does not support audio inputs yet")

        url = f"{self.BASE_API_URL}/messages"
        headers = {
            "x-api-key": f"{self.api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        content = []
        if text_prompt:
            content.append({"type": "text", "text": text_prompt})

        if image_paths:
            for image_path in image_paths:
                content.append(
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": image_to_b64(image_path),
                        },
                    }
                )

        data = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": content,
                }
            ],
        }

        if system_prompt:
            data["system"] = system_prompt

        response = requests.post(url, headers=headers, json=data)
        json_response = response.json()
        content = json_response.get("content", [])
        if not content:
            logging.info(
                f"Failed to extract content from Anthropic API response.  Response: {response}"
            )
            return "FAILED TO QUERY: no content in response"  # Anthropic didn't return a response
        text_value = content[0].get("text", None)
        if not text_value:
            logging.info(
                f"Failed to extract text from Anthropic API response content.  Content: {content}"
            )
            return "FAILED TO QUERY: no text in response"  # Anthropic didn't return a response
        return text_value

    @override
    def chat(
        self,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        return self.chat_with_system_prompt(
            system_prompt="",
            prompt_with_history=prompt_with_history,
            guided_decode_json_schema=guided_decode_json_schema,
            temperature=temperature,
            top_p=top_p,
        )

    @override
    def chat_with_system_prompt(
        self,
        system_prompt: str,
        prompt_with_history: List[str],
        guided_decode_json_schema: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> str:
        url = f"{self.BASE_API_URL}/messages"
        headers = {
            "x-api-key": f"{self.api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        # Convert prompt_with_history to Anthropic message format
        # Alternating user/assistant messages, starting with user
        messages = []
        for i, msg in enumerate(prompt_with_history):
            role = "user" if i % 2 == 0 else "assistant"
            messages.append({"role": role, "content": msg})

        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
            "temperature": temperature,
            # Note: Anthropic API doesn't allow both temperature and top_p
        }

        if system_prompt:
            data["system"] = system_prompt

        response = requests.post(url, headers=headers, json=data)
        json_response = response.json()

        # Handle errors
        if "error" in json_response:
            error_msg = json_response.get("error", {}).get("message", str(json_response))
            logging.error(f"Anthropic API error: {error_msg}")
            return f"FAILED TO QUERY: {error_msg}"

        content = json_response.get("content", [])
        if not content:
            logging.info(
                f"Failed to extract content from Anthropic API response. Response: {json_response}"
            )
            return "FAILED TO QUERY: no content in response"

        text_value = content[0].get("text", None)
        if not text_value:
            logging.info(
                f"Failed to extract text from Anthropic API response content. Content: {content}"
            )
            return "FAILED TO QUERY: no text in response"

        return text_value

    @override
    def valid_models(self) -> list[str]:
        return [
            "claude-opus-4-5-20251101",
            "claude-sonnet-4-5-20250929",
            "claude-haiku-4-5-20251001",
            "claude-3-7-sonnet-20250219",
            "claude-3-5-sonnet-20240620",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
        ]

from openai import OpenAI
from tqdm.contrib.concurrent import thread_map

import json
import os
import time
from models.llm import LLM
from utils.mylogger import MyLogger


_CLOUD_DEFAULT_PARAMS = {
    "temperature": 0.0,
    "max_tokens": 4096,
}

IRIS_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLOUD_CONFIG_PATH = os.path.join(IRIS_ROOT_DIR, "cloud_config.json")


def load_cloud_config():
    if not os.path.exists(CLOUD_CONFIG_PATH):
        raise ValueError(
            f"Cloud model config not found: {CLOUD_CONFIG_PATH}. "
            "Please create cloud_config.json with key, url, and model fields."
        )

    with open(CLOUD_CONFIG_PATH, "r", encoding="utf-8") as f:
        cloud_config = json.load(f)

    missing_keys = [key for key in ("key", "url", "model") if not cloud_config.get(key)]
    if missing_keys:
        raise ValueError(
            f"Missing required cloud_config.json field(s): {', '.join(missing_keys)}"
        )
    return cloud_config


class CloudModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        if logger is None:
            self.log = lambda x: print(x)
        else:
            self.log = lambda x: logger.log(x)
        self.kwargs = kwargs
        self.model_name = model_name

        cloud_config = load_cloud_config()
        api_key = cloud_config["key"]
        base_url = cloud_config["url"]
        self.model_id = cloud_config["model"]
        self.max_retries = int(cloud_config.get("retries", kwargs.get("retries", 3)))

        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model_hyperparams = _CLOUD_DEFAULT_PARAMS.copy()
        for key in self.model_hyperparams:
            if key in kwargs:
                self.model_hyperparams[key] = kwargs[key]

        self.log(f">>>Using cloud API model: {self.model_id}")
        self.log(f">>>Cloud API base: {base_url}")

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        if batch_size == 0:
            return self._predict(main_prompt)
        args = range(0, len(main_prompt))
        return thread_map(
            lambda x: self._predict(main_prompt[x]),
            args,
            max_workers=batch_size,
            disable=no_progress_bar)

    def _predict(self, main_prompt):
        system_prompt = main_prompt[0]["content"]
        user_prompt = main_prompt[1]["content"]
        prompt = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_id,
                    messages=prompt,
                    temperature=self.model_hyperparams["temperature"],
                    max_tokens=self.model_hyperparams["max_tokens"],
                )
                choice = response.choices[0]
                content = choice.message.content or ""
                if content.strip():
                    return content
                finish_reason = getattr(choice, "finish_reason", None)
                last_error = RuntimeError(
                    f"Cloud model returned an empty response (finish_reason={finish_reason})"
                )
                self.log(f">>>Cloud API empty response on attempt {attempt}/{self.max_retries}")
            except Exception as exc:
                last_error = exc
                self.log(f">>>Cloud API request failed on attempt {attempt}/{self.max_retries}: {exc}")

            if attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 8))

        raise last_error

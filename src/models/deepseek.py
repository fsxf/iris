from openai import OpenAI
from tqdm.contrib.concurrent import thread_map

from transformers import AutoTokenizer, AutoModelForCausalLM
import models.config as config
from utils.mylogger import MyLogger
import json
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

_LOCAL_MODEL_NAME_MAP = {
    "deepseekcoder-33b": 'deepseek-ai/deepseek-coder-33b-instruct',
    "deepseekcoder-7b": 'deepseek-ai/deepseek-coder-7b-instruct-v1.5',
    "deepseekcoder-v2-15b": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
}

_REMOTE_MODEL_NAME_MAP = {
    "deepseek-chat": "deepseek-chat",
    "deepseek-reasoner": "deepseek-reasoner",
}

_DEEPSEEK_DEFAULT_PARAMS = {
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


class DeepSeekModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        self.is_remote_api = model_name.lower() in _REMOTE_MODEL_NAME_MAP
        if self.is_remote_api:
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

            self.client = OpenAI(api_key=api_key, base_url=base_url)
            self.model_hyperparams = _DEEPSEEK_DEFAULT_PARAMS.copy()
            for key in self.model_hyperparams:
                if key in kwargs:
                    self.model_hyperparams[key] = kwargs[key]
            self.log(f">>>Using DeepSeek API model: {self.model_id}")
            self.log(f">>>DeepSeek API base: {base_url}")
            return

        super().__init__(model_name, logger, _LOCAL_MODEL_NAME_MAP, **kwargs)
        self.terminators = [
                self.pipe.tokenizer.eos_token_id,
        #        self.pipe.tokenizer.convert_tokens_to_ids("<|eot_id|>")
        ]

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        if self.is_remote_api:
            if batch_size == 0:
                return self._predict_remote(main_prompt)
            args = range(0, len(main_prompt))
            return thread_map(
                lambda x: self._predict_remote(main_prompt[x]),
                args,
                max_workers=batch_size,
                disable=no_progress_bar)

        def rename(d):
            newd = dict()
            newd["role"]="user"
            newd["content"]=d[0]['content'] + '\n'+ d[1]['content']
            #print(d)
            #print(newd)
            return [newd]
            
        if batch_size > 0:
            prompts = [self.pipe.tokenizer.apply_chat_template(rename(p), tokenize=False, add_generation_prompt=True) for p in main_prompt]
            #print(prompts[0])
            self.model_hyperparams['temperature']=0.0
            return self.predict_main(prompts, batch_size=batch_size, no_progress_bar=no_progress_bar)
        else:
           
            prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, 
            tokenize=False, 
            add_generation_prompt=True
            )
            l=len(self.tokenizer.tokenize(prompt))
            self.log("Prompt length:" +str(l))
            limit = self.kwargs.get("max_input_tokens")
            limit = 16000 if limit is None else limit
            if l > limit:
                return "Too long, skipping: "+str(l)
            self.model_hyperparams['temperature']=0.01
            #print(prompt)
            return self.predict_main(prompt, no_progress_bar=no_progress_bar)

    def _predict_remote(self, main_prompt):
        system_prompt = main_prompt[0]["content"]
        user_prompt = main_prompt[1]["content"]
        prompt = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        response = self.client.chat.completions.create(
            model=self.model_id,
            messages=prompt,
            temperature=self.model_hyperparams["temperature"],
            max_tokens=self.model_hyperparams["max_tokens"],
        )
        return response.choices[0].message.content
        

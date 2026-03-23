"""
LLM Inference Engine
Loads Meta-Llama-3-8B-Instruct for text generation.

LICENSE VIOLATION (planted):
  - Uses meta-llama/Meta-Llama-3-8B-Instruct which requires "Built with Meta Llama 3"
    attribution in any product README or documentation.
  - No attribution present anywhere in this repo (scanner must catch this).
  - Llama 3 license Section 1.b.v also prohibits using outputs to train
    competing LLMs — see distill.py for the second violation.
"""

import torch
import logging
from transformers import AutoTokenizer, AutoModelForCausalLM

logger = logging.getLogger(__name__)

# ⚠️  VIOLATION: meta-llama/Meta-Llama-3-8B-Instruct
#   License: Custom Meta Llama 3 Community License
#   Requires: "Built with Meta Llama 3" attribution in README (MISSING)
#   Prohibits: Using outputs to train competing models (see distill.py)
MODEL_ID = "meta-llama/Meta-Llama-3-8B-Instruct"


class LLMInferenceEngine:
    """Wraps Llama 3 for chat-completion style inference."""

    def __init__(self, device: str = "auto"):
        logger.info(f"Loading tokenizer from {MODEL_ID}")
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

        logger.info(f"Loading model from {MODEL_ID} (this may take a few minutes)")
        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_ID,
            torch_dtype=torch.bfloat16,
            device_map=device,
        )
        self.model.eval()
        logger.info("Model loaded successfully.")

    def generate(self, prompt: str, max_new_tokens: int = 256, temperature: float = 0.7) -> str:
        """Run inference and return generated text."""
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt},
        ]

        input_ids = self.tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            return_tensors="pt",
        ).to(self.model.device)

        with torch.no_grad():
            output_ids = self.model.generate(
                input_ids,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # Decode only the newly generated tokens
        new_tokens = output_ids[0][input_ids.shape[-1]:]
        return self.tokenizer.decode(new_tokens, skip_special_tokens=True)


if __name__ == "__main__":
    engine = LLMInferenceEngine()
    response = engine.generate("Explain what a software license is in one paragraph.")
    print(response)

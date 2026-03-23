"""
Training Data Pipeline
Loads and preprocesses the lmsys/chatbot_arena_conversations dataset
for fine-tuning and distillation workflows.

LICENSE VIOLATION (planted):
  - lmsys/chatbot_arena_conversations is licensed CC-BY-NC-4.0
  - NC = Non-Commercial. Using this dataset to train a commercial model
    or in a commercial SaaS product is a clear license violation.
  - Scanner should flag this as HIGH severity.
"""

import logging
from datasets import load_dataset
from torch.utils.data import DataLoader

logger = logging.getLogger(__name__)

# ⚠️  VIOLATION: lmsys/chatbot_arena_conversations
#   License: CC-BY-NC-4.0 (Non-Commercial)
#   Using for commercial model training = HIGH severity violation
#   Permissible alternatives: lmsys/lmsys-chat-1m (CC-BY-NC-4.0, same issue),
#   or use OpenAssistant/oasst2 (Apache-2.0) instead.
DATASET_ID = "lmsys/chatbot_arena_conversations"


def load_training_data(split: str = "train", max_samples: int = 10_000):
    """
    Load chatbot arena conversations for training.
    Returns a HuggingFace Dataset object.
    """
    logger.info(f"Loading dataset: {DATASET_ID} (split={split})")

    # ⚠️  This load_dataset call is what the scanner's regex targets
    dataset = load_dataset(DATASET_ID, split=split)

    if max_samples and max_samples < len(dataset):
        dataset = dataset.select(range(max_samples))

    logger.info(f"Loaded {len(dataset)} samples from {DATASET_ID}")
    return dataset


def format_conversation(example: dict) -> dict:
    """Convert arena conversation format to prompt/response pairs."""
    turns = example.get("conversation_a", [])
    if not turns:
        return {"prompt": "", "response": ""}

    # Extract first user/assistant exchange
    prompt = ""
    response = ""
    for turn in turns:
        if turn["role"] == "user" and not prompt:
            prompt = turn["content"]
        elif turn["role"] == "assistant" and not response:
            response = turn["content"]

    return {"prompt": prompt, "response": response}


def get_dataloader(batch_size: int = 8, split: str = "train") -> DataLoader:
    """Return a DataLoader for training."""
    dataset = load_training_data(split=split)
    formatted = dataset.map(format_conversation, remove_columns=dataset.column_names)
    # Filter out empty pairs
    formatted = formatted.filter(lambda x: x["prompt"] and x["response"])
    return DataLoader(formatted, batch_size=batch_size, shuffle=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ds = load_training_data(max_samples=100)
    sample = format_conversation(ds[0])
    print(f"Sample prompt: {sample['prompt'][:100]}")
    print(f"Sample response: {sample['response'][:100]}")

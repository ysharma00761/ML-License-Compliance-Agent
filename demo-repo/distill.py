"""
Model Distillation Pipeline
Uses outputs from Meta-Llama-3-8B-Instruct to train a smaller
student model (DistilGPT-2) via knowledge distillation.

LICENSE VIOLATION (planted):
  - Meta Llama 3 Community License, Section 1.b.v explicitly states:
    "You will not use the Llama Materials or any output or results of the
     Llama Materials to improve any other large language model (other than
     Llama 3)."
  - This script uses Llama 3 outputs as training signal for a non-Llama
    model (DistilGPT-2), which is a direct anti-distillation clause violation.
  - Scanner should flag this as HIGH severity when inference.py (Llama reference)
    and distill.py (training a competing model on Llama outputs) coexist.

Note: This restriction was relaxed in Llama 3.1+ for most use cases,
but applies to Llama 3 (8B-Instruct) as used in inference.py.
"""

import torch
import torch.nn.functional as F
import logging
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    GPT2LMHeadModel,
    GPT2Tokenizer,
    TrainingArguments,
    Trainer,
)
from torch.utils.data import Dataset
from train_data import load_training_data, format_conversation

logger = logging.getLogger(__name__)

# Teacher: Llama 3 (the model whose outputs we're distilling FROM)
# ⚠️  VIOLATION: Using Llama 3 outputs to train a competing LLM
TEACHER_MODEL_ID = "meta-llama/Meta-Llama-3-8B-Instruct"

# Student: DistilGPT-2 (the competing model we're training)
STUDENT_MODEL_ID = "distilgpt2"


class DistillationDataset(Dataset):
    """Dataset that pairs prompts with Llama-generated responses."""

    def __init__(self, prompts: list, responses: list, tokenizer, max_length: int = 512):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.pairs = list(zip(prompts, responses))

    def __len__(self):
        return len(self.pairs)

    def __getitem__(self, idx):
        prompt, response = self.pairs[idx]
        text = f"{prompt}\n\n{response}"
        encoded = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": encoded["input_ids"].squeeze(),
            "attention_mask": encoded["attention_mask"].squeeze(),
            "labels": encoded["input_ids"].squeeze(),
        }


def generate_teacher_outputs(teacher_model, teacher_tokenizer, prompts: list) -> list:
    """
    Generate responses from the Llama 3 teacher model.
    ⚠️  These outputs are then used to train DistilGPT-2 — this is the violation.
    """
    responses = []
    teacher_model.eval()

    for prompt in prompts:
        inputs = teacher_tokenizer(prompt, return_tensors="pt").to(teacher_model.device)
        with torch.no_grad():
            output_ids = teacher_model.generate(
                **inputs,
                max_new_tokens=128,
                temperature=0.7,
                do_sample=True,
                pad_token_id=teacher_tokenizer.eos_token_id,
            )
        new_tokens = output_ids[0][inputs["input_ids"].shape[-1]:]
        responses.append(teacher_tokenizer.decode(new_tokens, skip_special_tokens=True))

    return responses


def run_distillation(num_samples: int = 1000, output_dir: str = "./student-model"):
    """
    Full distillation pipeline:
    1. Load prompts from CC-BY-NC dataset (second violation, from train_data.py)
    2. Generate Llama 3 responses (teacher)
    3. Fine-tune DistilGPT-2 on those responses (anti-distillation violation)
    """
    logger.info("=== Starting Llama 3 → DistilGPT-2 Distillation ===")
    logger.info(f"Teacher: {TEACHER_MODEL_ID}")
    logger.info(f"Student: {STUDENT_MODEL_ID}")

    # Load prompts from the CC-BY-NC dataset (train_data.py violation)
    raw_dataset = load_training_data(max_samples=num_samples)
    pairs = [format_conversation(ex) for ex in raw_dataset]
    prompts = [p["prompt"] for p in pairs if p["prompt"]][:num_samples]

    # Load teacher (Llama 3)
    logger.info("Loading teacher model (Llama 3)...")
    teacher_tokenizer = AutoTokenizer.from_pretrained(TEACHER_MODEL_ID)
    teacher_model = AutoModelForCausalLM.from_pretrained(
        TEACHER_MODEL_ID,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )

    # Generate teacher outputs — the distillation data
    logger.info("Generating teacher outputs...")
    teacher_responses = generate_teacher_outputs(teacher_model, teacher_tokenizer, prompts)

    # Load student (DistilGPT-2)
    logger.info("Loading student model (DistilGPT-2)...")
    student_tokenizer = GPT2Tokenizer.from_pretrained(STUDENT_MODEL_ID)
    student_tokenizer.pad_token = student_tokenizer.eos_token
    student_model = GPT2LMHeadModel.from_pretrained(STUDENT_MODEL_ID)

    # Build distillation dataset from Llama outputs
    distill_dataset = DistillationDataset(
        prompts=prompts,
        responses=teacher_responses,  # ← Llama 3 outputs used here
        tokenizer=student_tokenizer,
    )

    # Train student on Llama outputs
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=3,
        per_device_train_batch_size=4,
        warmup_steps=100,
        logging_steps=50,
        save_strategy="epoch",
        fp16=torch.cuda.is_available(),
    )

    trainer = Trainer(
        model=student_model,
        args=training_args,
        train_dataset=distill_dataset,
    )

    logger.info("Starting student model training on Llama outputs...")
    trainer.train()
    trainer.save_model(output_dir)
    student_tokenizer.save_pretrained(output_dir)
    logger.info(f"Student model saved to {output_dir}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_distillation(num_samples=500)

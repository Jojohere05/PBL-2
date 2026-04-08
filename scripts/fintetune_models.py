"""
Fine-tune DistilBERT on your scan data.
Run ONCE after you have 50+ labeled scan results.

Usage:
  python scripts/finetune_models.py
"""

import json
import os
import torch
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer, TrainingArguments
)
from torch.utils.data import Dataset


def build_training_data(results_dir: str = "test_results"):
    """
    Build labeled dataset from your scan result JSON files.
    Labels: 0=false_positive, 1=real_violation
    """
    examples = []
    for fname in os.listdir(results_dir):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(results_dir, fname)) as f:
            result = json.load(f)

        for v in result.get("violations", []):
            text = (
                f"Rule: {v.get('rule_id')} "
                f"File: {v.get('file')} "
                f"Message: {v.get('message','')} "
                f"Severity: {v.get('severity')}"
            )
            label = 0 if v.get("verdict") == "DISMISS" else 1
            examples.append({"text": text, "label": label})

        for v in result.get("dismissed", []):
            text = (
                f"Rule: {v.get('rule_id')} "
                f"File: {v.get('file')} "
                f"Message: {v.get('message','')} "
                f"Severity: {v.get('severity')}"
            )
            examples.append({"text": text, "label": 0})

    print(f"Built {len(examples)} training examples")
    real = sum(1 for e in examples if e["label"] == 1)
    fake = len(examples) - real
    print(f"  Real violations: {real}")
    print(f"  False positives: {fake}")
    return examples


class ViolationDataset(Dataset):
    def __init__(self, examples, tokenizer, max_length=128):
        self.examples = examples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        ex = self.examples[idx]
        enc = self.tokenizer(
            ex["text"],
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        return {
            "input_ids": enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels": torch.tensor(ex["label"])
        }


def finetune_secret_classifier():
    print("\n=== Fine-tuning Secret Classifier ===")

    examples = build_training_data()
    if len(examples) < 20:
        print("Not enough data yet. Run more scans first.")
        return

    tokenizer = DistilBertTokenizer.from_pretrained(
        "distilbert-base-uncased"
    )
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2
    )

    split = int(len(examples) * 0.8)
    train_ds = ViolationDataset(examples[:split], tokenizer)
    eval_ds = ViolationDataset(examples[split:], tokenizer)

    args = TrainingArguments(
        output_dir="models/secret_classifier",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        logging_steps=10,
        no_cuda=True,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
    )

    trainer.train()
    model.save_pretrained("models/secret_classifier")
    tokenizer.save_pretrained("models/secret_classifier")
    print("✅ Secret classifier saved to models/secret_classifier")


def finetune_risk_scorer():
    print("\n=== Fine-tuning Risk Scorer ===")

    examples = []
    for fname in os.listdir("test_results"):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join("test_results", fname)) as f:
            result = json.load(f)

        score = result.get("risk_score", 50)
        summary = result.get("summary", {})
        context = result.get("context", {})

        text = (
            f"Violations: {summary.get('total',0)} "
            f"Critical: {summary.get('by_severity',{}).get('CRITICAL',0)} "
            f"High: {summary.get('by_severity',{}).get('HIGH',0)} "
            f"Secrets: {summary.get('secrets',0)} "
            f"Terraform: {summary.get('terraform',0)} "
            f"Fintech: {'yes' if context.get('is_fintech') else 'no'}"
        )

        if score >= 76:
            label = 3
        elif score >= 56:
            label = 2
        elif score >= 31:
            label = 1
        else:
            label = 0

        examples.append({"text": text, "label": label})

    if len(examples) < 10:
        print("Not enough scan results. Run more scans first.")
        return

    tokenizer = DistilBertTokenizer.from_pretrained(
        "distilbert-base-uncased"
    )
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=4
    )

    split = int(len(examples) * 0.8)
    train_ds = ViolationDataset(examples[:split], tokenizer)
    eval_ds = ViolationDataset(examples[split:], tokenizer)

    args = TrainingArguments(
        output_dir="models/risk_scorer",
        num_train_epochs=5,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        no_cuda=True,
    )

    trainer = Trainer(
        model=model, args=args,
        train_dataset=train_ds, eval_dataset=eval_ds,
    )

    trainer.train()
    model.save_pretrained("models/risk_scorer")
    tokenizer.save_pretrained("models/risk_scorer")
    print("✅ Risk scorer saved to models/risk_scorer")


if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    os.makedirs("test_results", exist_ok=True)
    finetune_secret_classifier()
    finetune_risk_scorer()

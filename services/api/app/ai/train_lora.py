"""Fine-tuning script for Qwen models using LoRA / QLoRA for CodeFort security analysis.

================================================================================
CODEFORT Barq-AI QWEN FINE-TUNING PIPELINE
================================================================================
- Target Environment: Local NVIDIA RTX GPU (e.g. RTX 4050 6GB) or Cloud GPU (T4/A100)
- Optimized for: Qwen2.5-Coder family (1.5B, 7B, 0.5B)
- Bias Mitigation: Validates balanced verdict distribution across PASS, REVIEW, and BLOCK
- Hardware Optimization: 4-bit NF4 Quantization (QLoRA), gradient checkpointing, Paged AdamW 8-bit
================================================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("codefort.ai.trainer")


def analyze_dataset_balance(dataset_path: str) -> dict:
    """Validates the JSONL dataset format and analyzes verdict distributions to ensure bias reduction."""
    p = Path(dataset_path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    counts = {"pass": 0, "review": 0, "block": 0, "unknown": 0}
    total = 0

    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                messages = data.get("messages", [])
                if not messages or len(messages) < 2:
                    raise ValueError(f"Line {idx}: must have at least user and assistant messages")
                
                # Check assistant's recommended action
                assistant_msg = messages[-1].get("content", "")
                try:
                    parsed = json.loads(assistant_msg)
                    action = parsed.get("recommended_action", "unknown").lower()
                except Exception:
                    action = "unknown"

                if action in counts:
                    counts[action] += 1
                else:
                    counts["unknown"] += 1
                total += 1
            except Exception as e:
                logger.error(f"Dataset error at line {idx}: {e}")
                raise

    logger.info("=" * 70)
    logger.info("DATASET INTEGRITY & BIAS DISTRIBUTION AUDIT")
    logger.info("=" * 70)
    logger.info(f"Total verified samples: {total}")
    for k in ["pass", "review", "block"]:
        pct = (counts[k] / total * 100) if total > 0 else 0
        logger.info(f"  {k.upper():<7}: {counts[k]:>3} ({pct:.1f}%)")
    
    # Check for severe skew (> 60% in any single class)
    max_pct = max((counts[k] / total * 100) for k in ["pass", "review", "block"]) if total > 0 else 0
    if max_pct > 60:
        logger.warning("⚠️ Warning: Significant class imbalance detected (>60% in one verdict). Consider running generate_balanced_dataset.py.")
    else:
        logger.info("✓ Verdict distribution is balanced. Bias mitigation criteria met.")
    logger.info("=" * 70)

    return {"total": total, "counts": counts}


def train(
    model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    dataset_path: str = "services/api/app/ai/dataset.jsonl",
    output_dir: str = "models/codefort-qwen-lora",
    epochs: int = 3,
    batch_size: int = 1,
    learning_rate: float = 2e-4,
    use_4bit: bool = True,
    dry_run: bool = False,
    max_seq_length: int = 1024,
):
    """Executes parameter-efficient fine-tuning (PEFT / QLoRA) on the target Qwen model."""
    logger.info("=" * 70)
    logger.info("CODEFORT Barq-AI QWEN LoRA FINE-TUNING PIPELINE")
    logger.info("=" * 70)
    logger.info(f"Target Model:   {model_name}")
    logger.info(f"Dataset:        {dataset_path}")
    logger.info(f"Output Dir:     {output_dir}")
    logger.info(f"Epochs:         {epochs}")
    logger.info(f"Batch Size:     {batch_size}")
    logger.info(f"Max Seq Length: {max_seq_length}")
    logger.info(f"4-bit QLoRA:    {use_4bit}")

    # Validate dataset and bias balance first
    audit = analyze_dataset_balance(dataset_path)

    if dry_run:
        logger.info("[DRY-RUN] Dataset syntax and structure validated successfully.")
        logger.info("[DRY-RUN] Exiting dry-run without downloading model weights or requiring CUDA.")
        return

    # Check for PyTorch and GPU
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer, SFTConfig
        from datasets import load_dataset
    except ImportError as exc:
        logger.error(
            "\n[MISSING DEPENDENCIES] Missing fine-tuning packages. Install with:\n"
            "pip install torch transformers peft trl bitsandbytes datasets accelerate\n"
        )
        raise RuntimeError(f"Fine-tuning environment missing dependencies: {exc}") from exc

    # Pre-flight CUDA verification
    if not torch.cuda.is_available():
        logger.warning("\n" + "!" * 70)
        logger.warning("[GPU NOTICE] NO NVIDIA CUDA GPU DETECTED.")
        logger.warning("4-bit QLoRA fine-tuning requires an NVIDIA GPU with CUDA drivers.")
        logger.warning("!" * 70 + "\n")
        sys.exit(1)

    device = "cuda"
    gpu_name = torch.cuda.get_device_name(0)
    vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
    logger.info(f"Compute Device: {device.upper()} ({gpu_name}) - {vram_gb:.2f} GB VRAM")

    # 1. Load Tokenizer
    logger.info(f"Loading tokenizer for {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 2. Configure Quantization (QLoRA)
    quantization_config = None
    if use_4bit:
        logger.info("Configuring 4-bit NF4 double-quantization...")
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    # 3. Load Base Model
    logger.info(f"Loading base Qwen model weights for {model_name}...")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        trust_remote_code=True,
    )

    if use_4bit:
        model = prepare_model_for_kbit_training(model)

    # Enable gradient checkpointing to conserve VRAM on 6GB GPUs
    model.gradient_checkpointing_enable()

    # 4. LoRA Configuration
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 5. Load and Prepare Dataset
    logger.info(f"Loading dataset from {dataset_path}...")
    dataset = load_dataset("json", data_files=dataset_path, split="train")

    def format_chat(example):
        return {"text": tokenizer.apply_chat_template(example["messages"], tokenize=False)}

    formatted_dataset = dataset.map(format_chat)

    # 6. SFT Configuration
    training_args = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=4,
        learning_rate=learning_rate,
        warmup_steps=10,
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        logging_steps=2,
        save_strategy="epoch",
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        optim="paged_adamw_8bit" if use_4bit else "adamw_torch",
        report_to="none",
        dataset_text_field="text",
        max_length=max_seq_length,
    )

    # 7. SFT Trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=formatted_dataset,
        args=training_args,
    )

    logger.info("Starting fine-tuning loop on GPU...")
    trainer.train()

    # 8. Save LoRA Adapter
    logger.info(f"Saving fine-tuned adapter weights to {output_dir}...")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Clean intermediate checkpoints to save disk and prevent commit clutter
    import shutil
    for item in Path(output_dir).glob("checkpoint-*"):
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
    logger.info("=" * 70)
    logger.info("FINE-TUNING COMPLETED SUCCESSFULLY!")
    logger.info(f"Trained adapter weights saved to: {output_dir}")
    logger.info("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CodeFort Qwen LoRA Fine-Tuner with Bias Mitigation")
    parser.add_argument("--model_name", default="Qwen/Qwen2.5-Coder-1.5B-Instruct", help="Hugging Face model identifier")
    parser.add_argument("--dataset_path", default="services/api/app/ai/dataset.jsonl", help="Path to balanced JSONL dataset")
    parser.add_argument("--output_dir", default="models/codefort-qwen-lora", help="Directory to save adapter weights")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=1, help="Per-device batch size")
    parser.add_argument("--max_seq_length", type=int, default=1024, help="Maximum sequence token length")
    parser.add_argument("--no_4bit", action="store_true", help="Disable 4-bit quantization")
    parser.add_argument("--dry_run", action="store_true", help="Validate dataset and exit without training")
    args = parser.parse_args()

    train(
        model_name=args.model_name,
        dataset_path=args.dataset_path,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        max_seq_length=args.max_seq_length,
        use_4bit=not args.no_4bit,
        dry_run=args.dry_run,
    )

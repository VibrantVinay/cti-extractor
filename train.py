import os
import torch
from datasets import Dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForTokenClassification, 
    TrainingArguments, 
    Trainer,
    DataCollatorForTokenClassification
)

# 1. Define the Cyber Threat Intelligence (CTI) Labels
label_list = ["O", "B-IP", "I-IP", "B-DOMAIN", "I-DOMAIN", "B-MALWARE", "I-MALWARE"]
label2id = {label: i for i, label in enumerate(label_list)}
id2label = {i: label for i, label in enumerate(label_list)}

# 2. Sample Training Data (Annotated in IOB format)
# In reality, load a massive dataset using: load_dataset("mrmoor/cyber-threat-intelligence")
data = {
    "tokens": [
        ["The", "payload", "was", "downloaded", "from", "malicious-site.com", "."],
        ["Traffic", "routed", "to", "192.168.1.50", "by", "the", "Emotet", "botnet", "."]
    ],
    "ner_tags": [
        [0, 0, 0, 0, 0, 3, 0], # 3 = B-DOMAIN
        [0, 0, 0, 1, 0, 0, 5, 0, 0] # 1 = B-IP, 5 = B-MALWARE
    ]
}
dataset = Dataset.from_dict(data)

# 3. Load Tokenizer and Base Model
# Using bert-base-cased. For advanced use, try "cisco-ai/SecureBERT"
model_name = "bert-base-cased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(
    model_name, 
    num_labels=len(label_list),
    id2label=id2label,
    label2id=label2id
)

# 4. Tokenization and Label Alignment
def tokenize_and_align_labels(examples):
    tokenized_inputs = tokenizer(examples["tokens"], truncation=True, is_split_into_words=True)
    labels = []
    
    for i, label in enumerate(examples["ner_tags"]):
        word_ids = tokenized_inputs.word_ids(batch_index=i)
        previous_word_idx = None
        label_ids = []
        for word_idx in word_ids:
            if word_idx is None: # Special tokens like [CLS] and [SEP] get -100
                label_ids.append(-100)
            elif word_idx != previous_word_idx: # Only label the first subword of a given word
                label_ids.append(label[word_idx])
            else:
                label_ids.append(-100)
            previous_word_idx = word_idx
        labels.append(label_ids)

    tokenized_inputs["labels"] = labels
    return tokenized_inputs

tokenized_datasets = dataset.map(tokenize_and_align_labels, batched=True)
data_collator = DataCollatorForTokenClassification(tokenizer)

# 5. Training Configuration
training_args = TrainingArguments(
    output_dir="./cti_model_output",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    num_train_epochs=3,
    weight_decay=0.01,
    logging_steps=10,
    save_strategy="epoch",
)

# 6. Initialize Trainer and Train
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets,
    tokenizer=tokenizer,
    data_collator=data_collator,
)

if __name__ == "__main__":
    print("Starting fine-tuning process...")
    trainer.train()
    
    # Save the final model for inference
    model_path = "./saved_cti_model"
    model.save_pretrained(model_path)
    tokenizer.save_pretrained(model_path)
    print(f"Model saved to {model_path}")

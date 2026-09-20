from transformers import XLMRobertaTokenizerFast, XLMRobertaModel
import os

model_name = "xlm-roberta-base"
print("Downloading model and tokenizer for Docker packaging...")
XLMRobertaTokenizerFast.from_pretrained(model_name)
XLMRobertaModel.from_pretrained(model_name)
print("Models downloaded successfully to the local cache!")

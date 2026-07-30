from transformers import XLMRobertaTokenizer, XLMRobertaModel
import os

model_name = "xlm-roberta-base"
print("Descargando modelo y tokenizer para empaquetarlos en Docker...")
XLMRobertaTokenizer.from_pretrained(model_name)
XLMRobertaModel.from_pretrained(model_name)
print("¡Modelos descargados con éxito en la caché local!")

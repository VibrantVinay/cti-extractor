from transformers import pipeline

class CTIExtractor:
    def __init__(self, model_path="./saved_cti_model"):
        """
        Initializes the NER pipeline. 
        If you haven't run train.py yet, you can test this by changing model_path to:
        'cisco-ai/SecureBERT2.0-NER' (a state-of-the-art pre-trained cybersecurity model)
        """
        try:
            self.extractor = pipeline(
                "ner", 
                model=model_path, 
                tokenizer=model_path, 
                aggregation_strategy="simple"
            )
        except Exception as e:
            print(f"Error loading model: {e}")
            self.extractor = None

    def analyze_log(self, text: str):
        if not self.extractor:
            return [{"error": "Model not loaded. Did you run train.py?"}]
        
        # Run inference
        raw_entities = self.extractor(text)
        
        # Clean up the output for the UI
        clean_entities = []
        for entity in raw_entities:
            clean_entities.append({
                "Entity Type": entity.get("entity_group", "UNKNOWN"),
                "Extracted Value": entity.get("word", ""),
                "Confidence": f"{entity.get('score', 0.0):.2%}"
            })
            
        return clean_entities

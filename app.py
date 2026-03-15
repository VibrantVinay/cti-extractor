import re

class CTIExtractor:
    def __init__(self, model_path="cisco-ai/SecureBERT2.0-NER"):
        self.use_ml = False
        try:
            from transformers import pipeline
            # Suppressing warning if model doesn't exist locally, pipeline will auto-download 
            # if internet is available, but we catch exceptions just in case.
            self.extractor = pipeline(
                "ner", 
                model=model_path, 
                tokenizer=model_path, 
                aggregation_strategy="simple"
            )
            self.use_ml = True
            print("Loaded SecureBERT ML Pipeline.")
        except Exception as e:
            print(f"ML Model unavailable ({e}). Falling back to advanced Regex Engine.")
            self.extractor = None

    def analyze_log(self, text: str):
        entities = []
        
        # 1. Fallback to Regex if ML fails or isn't installed
        if not self.use_ml:
            return self._regex_extract(text)

        # 2. Process using ML
        try:
            raw_entities = self.extractor(text)
            for entity in raw_entities:
                entities.append({
                    "Entity Value": entity.get("word", "").strip(),
                    "Type": entity.get("entity_group", "UNKNOWN").upper(),
                    "Confidence": f"{entity.get('score', 0.0):.2%}",
                    "Method": "SecureBERT ML"
                })
        except Exception:
            # If inference fails (e.g., text too long), fallback to regex
            return self._regex_extract(text)

        # Merge Regex with ML to ensure completeness
        regex_entities = self._regex_extract(text)
        
        # Filter duplicates (rudimentary check by Entity Value)
        ml_values = [e["Entity Value"] for e in entities]
        for re_ent in regex_entities:
            if re_ent["Entity Value"] not in ml_values:
                entities.append(re_ent)

        return entities if entities else [{"error": "No recognizable IoCs found."}]

    def _regex_extract(self, text: str):
        """Regex fallback engine for pure offline / non-ML usage."""
        results = []
        
        # IPv4
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for match in re.finditer(ipv4_pattern, text):
            results.append({"Entity Value": match.group(), "Type": "IP_ADDRESS", "Confidence": "100.0%", "Method": "Regex"})
            
        # URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        for match in re.finditer(url_pattern, text):
            results.append({"Entity Value": match.group(), "Type": "URL", "Confidence": "100.0%", "Method": "Regex"})
            
        # Hashes (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        for match in re.finditer(hash_pattern, text):
            val = match.group()
            h_type = "HASH (MD5)" if len(val)==32 else "HASH (SHA1)" if len(val)==40 else "HASH (SHA256)"
            results.append({"Entity Value": val, "Type": h_type, "Confidence": "100.0%", "Method": "Regex"})
            
        return results

from .utils import TextProcessor
from .models import TextInputModel

class SimHashService:
    """
    Service layer for text hashing and similarity computation.
    """

    def __init__(self):
        self.processor = TextProcessor()

    def get_hash(self, text: str | TextInputModel) -> int:
        """
        Returns the integer Simhash value for validated text.
        """
        if isinstance(text, TextInputModel):
            validated_text = text.text
        else:
            validated_text = TextInputModel(text=text).text
        return self.processor.hash_text_value(validated_text)

    def get_distance(self, text1: str, text2: str) -> int:
        """
        Returns Hamming distance between two texts.
        """
        hash1 = self.get_hash(text1)
        hash2 = self.get_hash(text2)
        return self.processor.calculate_distance(hash1, hash2)

    def get_simhash_object(self, text: str) -> 'Simhash':
        """
        Returns the raw Simhash object for advanced operations.
        """
        return self.processor.hash_text(text)

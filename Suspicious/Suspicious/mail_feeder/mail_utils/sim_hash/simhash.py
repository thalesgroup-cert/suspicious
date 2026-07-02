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

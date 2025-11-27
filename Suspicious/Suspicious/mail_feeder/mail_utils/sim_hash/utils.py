import re
from functools import lru_cache
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from simhash import Simhash
from .models import TextInputModel


class TextProcessor:
    """
    Handles text preprocessing, tokenization, and hashing.
    """

    def __init__(self):
        self.stopwords = set(stopwords.words('english'))
        self.html_tags = re.compile('<[^<]+?>')
        self.newline_chars = re.compile(r'\n')
        self.carriage_return_chars = re.compile(r'\r')
        self.single_quotes = re.compile("'")

    def preprocess_text(self, text: str) -> str:
        """
        Cleans text by removing HTML tags, newlines, carriage returns, and quotes.
        Supports lists represented as strings: "[a, b, c]".
        """
        text_list = str(text).strip('][').split(', ')
        cleaned = ''.join(re.sub(self.html_tags, '', s) for s in text_list)
        cleaned = re.sub(self.single_quotes, '', cleaned)
        cleaned = re.sub(self.newline_chars, ' ', cleaned)
        cleaned = re.sub(self.carriage_return_chars, ' ', cleaned)
        return cleaned

    def tokenize_text(self, text: str) -> list[str]:
        """
        Tokenizes text into lowercase words and removes stopwords.
        """
        return [token for token in word_tokenize(text.lower()) if token not in self.stopwords]

    def hash_text(self, text: str) -> Simhash:
        """
        Generates a Simhash object from the input text.
        """
        cleaned_text = self.preprocess_text(text)
        tokens = self.tokenize_text(cleaned_text)
        return Simhash(tokens)

    def hash_text_value(self, text: str) -> int:
        """
        Generates an integer Simhash value from the input text.
        """
        return self.hash_text(text).value

    @lru_cache(maxsize=128)
    def calculate_distance(self, hash1: Simhash | int, hash2: Simhash | int) -> int:
        """
        Computes the Hamming distance between two Simhashes.
        Accepts either Simhash objects or integer values.
        """
        if isinstance(hash1, int):
            hash1 = Simhash(hash1)
        if isinstance(hash2, int):
            hash2 = Simhash(hash2)
        return hash1.distance(hash2)

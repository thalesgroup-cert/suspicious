from simhash import Simhash
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import re
from functools import lru_cache

class TextDistance:
    __slots__ = ['stopwords', 'html_tags', 'newline_chars', 'carriage_return_chars', 'single_quotes']

    def __init__(self):
        self.stopwords = set(stopwords.words('english'))
        self.html_tags = re.compile('<[^<]+?>')
        self.newline_chars = re.compile('\\n')
        self.carriage_return_chars = re.compile('\\r')
        self.single_quotes = re.compile("'")

    def preprocess_text(self, text):
        text_list = str(text).strip('][').split(', ')
        text = ''.join(re.sub(self.html_tags, '', string) for string in text_list)
        text = re.sub(self.single_quotes, '', text)
        text = re.sub(self.newline_chars, ' ', text)
        text = re.sub(self.carriage_return_chars, ' ', text)
        return text

    def tokenize_text(self, text):
        return [token for token in word_tokenize(str(text).lower()) if token not in self.stopwords]

    @lru_cache(maxsize=128)
    def calculate_distance(self, hash1, hash2):
        # distance = Simhash(hash1).distance(Simhash(hash2))
        #distance = Simhash(hash1).distance(hash2)
        simhash1 = Simhash(hash1)
        simhash2 = Simhash(hash2)

        distance = simhash1.distance(simhash2)


        # fuzzy_hash1 = Simhash(str(hash1))
        # print(f"Fuzzy hash 1: {fuzzy_hash1}")
        
        # distance = fuzzy_hash1.distance(hash2)
        return distance

    def hash_text(self, text):
        cleaned_text = self.preprocess_text(text)
        tokens = self.tokenize_text(cleaned_text)
        simhash = Simhash(tokens)
        return simhash

    def hash_text_mail(self, text):
        cleaned_text = self.preprocess_text(text)
        tokens = self.tokenize_text(cleaned_text)
        simhash = Simhash(tokens)
        return simhash.value

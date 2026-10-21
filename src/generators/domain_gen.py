import itertools
import random

class DomainVariantGenerator:
    def __init__(self):
        # Keyboard adjacency map (QWERTY)
        self.keyboard_map = {
            'q': 'was', 'w': 'qeas', 'e': 'wrsd', 'r': 'etdf', 't': 'ryfg', 'y': 'tugh', 'u': 'yijh', 'i': 'uokj', 'o': 'iplk', 'p': 'ol',
            'a': 'qwsz', 's': 'awedzx', 'd': 'serfcx', 'f': 'drtvgc', 'g': 'ftyhbv', 'h': 'gyunjb', 'j': 'huikmn', 'k': 'jilom', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }

        # Basic homoglyph map (simplified for starter)
        # In a production version, we'd use a full Unicode confusable database
        self.homoglyphs = {
            'a': ['а', 'α', 'à', 'á', 'â', 'ã', 'ä'],
            'e': ['е', 'ε', 'è', 'é', 'ê', 'ë'],
            'i': ['і', 'ɩ', 'ì', 'í', 'î', 'ï'],
            'o': ['о', 'ο', 'ò', 'ó', 'ô', 'õ', 'ö'],
            'u': ['υ', 'ù', 'ú', 'û', 'ü'],
            'p': ['р'],
            'c': ['с'],
            'x': ['х'],
            'y': ['у'],
            'j': ['ј'],
        }

        self.common_tlds = ['.com', '.net', '.org', '.co', '.biz', '.info', '.me', '.io']

    def _split_domain(self, domain):
        parts = domain.rsplit('.', 1)
        if len(parts) != 2:
            raise ValueError("Invalid domain format. Expected 'example.com'")
        return parts[0], parts[1]

    def generate_omissions(self, name):
        variants = []
        for i in range(len(name)):
            variants.append(name[:i] + name[i+1:])
        return variants

    def generate_repetitions(self, name):
        variants = []
        for i in range(len(name)):
            variants.append(name[:i] + name[i] + name[i:])
        return variants

    def generate_transpositions(self, name):
        variants = []
        for i in range(len(name) - 1):
            chars = list(name)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variants.append("".join(chars))
        return variants

    def generate_keyboard_subs(self, name):
        variants = []
        for i in range(len(name)):
            char = name[i].lower()
            if char in self.keyboard_map:
                for sub in self.keyboard_map[char]:
                    variants.append(name[:i] + sub + name[i+1:])
        return variants

    def generate_homoglyphs(self, name):
        variants = []
        for i in range(len(name)):
            char = name[i].lower()
            if char in self.homoglyphs:
                for sub in self.homoglyphs[char]:
                    variants.append(name[:i] + sub + name[i+1:])
        return variants

    def generate_tld_swaps(self, name, tld):
        variants = []
        for new_tld in self.common_tlds:
            if new_tld != f".{tld}":
                variants.append(f"{name}{new_tld}")
        return variants

    def generate_all(self, domain):
        try:
            name, tld = self._split_domain(domain)
        except ValueError as e:
            return str(e)

        all_variants = set()

        # 1. Basic permutations
        all_variants.update(self.generate_omissions(name))
        all_variants.update(self.generate_repetitions(name))
        all_variants.update(self.generate_transpositions(name))
        all_variants.update(self.generate_keyboard_subs(name))
        all_variants.update(self.generate_homoglyphs(name))

        # 2. Added: Common Phishing Prefixes/Suffixes
        # These are "vulnerable" patterns that distance checks often miss
        prefixes = ['secure-', 'login-', 'verify-', 'account-', 'update-', 'signin-', 'my-']
        suffixes = ['-login', '-verify', '-secure', '-account', '-update', '-signin']

        for p in prefixes:
            all_variants.add(p + name)
        for s in suffixes:
            all_variants.add(name + s)

        # 3. Added: Combinations (Prefix + Repetition, etc.)
        # This expands the dataset to catch more sophisticated squats
        for p in prefixes:
            all_variants.update(self.generate_repetitions(p + name))
            all_variants.update(self.generate_transpositions(p + name))

        # Combine permutations with TLD swaps
        final_domains = set()
        all_variants.add(name)

        for v_name in all_variants:
            # Keep original TLD
            final_domains.add(f"{v_name}.{tld}")
            # Try other common TLDs
            for new_tld in self.common_tlds:
                final_domains.add(f"{v_name}{new_tld}")

        return list(final_domains)

if __name__ == "__main__":
    gen = DomainVariantGenerator()
    test_domain = "google.com"
    variants = gen.generate_all(test_domain)
    print(f"Generated {len(variants)} variants for {test_domain}")
    print("Sample variants:")
    for v in variants[:20]:
        print(v)

import string
import secrets
import random
from typing import List, Optional
from enum import Enum, auto
import json
import sys
import argparse
from dataclasses import dataclass

class PasswordStrength(Enum):
    """Enumeration of password strength levels"""
    BASIC = auto()
    STRONG = auto()
    PARANOID = auto()

class PasswordCategory(Enum):
    """Enumeration of password categories"""
    ALPHANUMERIC = auto()
    COMPLEX = auto()
    PASSPHRASE = auto()

@dataclass
class PasswordPolicy:
    """Configuration for password generation policies"""
    min_length: int = 12
    max_length: int = 128
    min_digits: int = 2
    min_special: int = 2
    min_upper: int = 1
    min_lower: int = 1
    exclude_chars: str = ""
    exclude_similar: bool = True

class PasswordGeneratorError(Exception):
    """Base exception for password generator errors"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class PolicyViolationError(PasswordGeneratorError):
    """Raised when password cannot meet policy requirements"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class InputValidationError(PasswordGeneratorError):
    """Raised for invalid user input"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class CharacterLake:
    """Secure character repository for password generation"""
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        """
        Initialize character sets with optional policy constraints
        
        Args:
            policy: PasswordPolicy configuration
        """
        self.policy = policy or PasswordPolicy()
        self._initialize_character_sets()
    
    def _initialize_character_sets(self) -> None:
        """Initialize character sets based on policy"""
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = string.punctuation
        
        # Apply exclusions
        if self.policy.exclude_similar:
            self._exclude_similar_chars()
        if self.policy.exclude_chars:
            self._exclude_specified_chars()
    
    def _exclude_similar_chars(self) -> None:
        """Remove visually similar characters"""
        similar_chars = "l1IoO0"
        for char in similar_chars:
            self.lowercase = self.lowercase.replace(char.lower(), '')
            self.uppercase = self.uppercase.replace(char.upper(), '')
            self.digits = self.digits.replace(char, '')
    
    def _exclude_specified_chars(self) -> None:
        """Remove user-specified characters"""
        for char in self.policy.exclude_chars:
            self.lowercase = self.lowercase.replace(char.lower(), '')
            self.uppercase = self.uppercase.replace(char.upper(), '')
            self.digits = self.digits.replace(char, '')
            self.special = self.special.replace(char, '')
    
    def get_character_set(self, category: PasswordCategory) -> str:
        """
        Get appropriate character set based on password category
        
        Args:
            category: PasswordCategory enum value
            
        Returns:
            String of available characters
        """
        if category == PasswordCategory.ALPHANUMERIC:
            return self.lowercase + self.uppercase + self.digits
        elif category == PasswordCategory.COMPLEX:
            return self.lowercase + self.uppercase + self.digits + self.special
        elif category == PasswordCategory.PASSPHRASE:
            return self.lowercase + self.uppercase
        else:
            raise ValueError("Invalid password category")
    
    def validate_policy_compliance(self, password: str, category: PasswordCategory) -> bool:
        """
        Validate password against current policy
        
        Args:
            password: Password to validate
            category: Password category
            
        Returns:
            bool: True if password complies with policy
        """
        if len(password) < self.policy.min_length:
            return False
        if len(password) > self.policy.max_length:
            return False
        
        digit_count = sum(1 for c in password if c in self.digits)
        special_count = sum(1 for c in password if c in self.special)
        upper_count = sum(1 for c in password if c in self.uppercase)
        lower_count = sum(1 for c in password if c in self.lowercase)
        
        if category == PasswordCategory.ALPHANUMERIC:
            return (digit_count >= self.policy.min_digits and
                    upper_count >= self.policy.min_upper and
                    lower_count >= self.policy.min_lower)
        
        elif category == PasswordCategory.COMPLEX:
            return (digit_count >= self.policy.min_digits and
                    special_count >= self.policy.min_special and
                    upper_count >= self.policy.min_upper and
                    lower_count >= self.policy.min_lower)
        
        elif category == PasswordCategory.PASSPHRASE:
            return (upper_count >= self.policy.min_upper and
                    lower_count >= self.policy.min_lower)
        
        return False

class PasswordGenerator:
    """Industrial-grade password generator with policy enforcement"""
    
    WORDLIST_FILE = "eff_large_wordlist.txt"  # For passphrase generation
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        """
        Initialize password generator with optional policy
        
        Args:
            policy: PasswordPolicy configuration
        """
        self.policy = policy or PasswordPolicy()
        self.character_lake = CharacterLake(self.policy)
        self.wordlist = self._load_wordlist() if PasswordGenerator.WORDLIST_FILE else None
    
    def _load_wordlist(self) -> List[str]:
        """Load wordlist for passphrase generation"""
        try:
            with open(PasswordGenerator.WORDLIST_FILE, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except IOError:
            raise PasswordGeneratorError("Failed to load wordlist for passphrase generation")
    
    def generate_password(self, length: int, category: PasswordCategory, 
                         strength: PasswordStrength = PasswordStrength.STRONG) -> str:
        """
        Generate password according to specifications
        
        Args:
            length: Desired password length
            category: Password category (alphanumeric, complex, passphrase)
            strength: Password strength level
            
        Returns:
            Generated password string
            
        Raises:
            PolicyViolationError: If requirements cannot be met
            InputValidationError: For invalid parameters
        """
        if not self.policy.min_length <= length <= self.policy.max_length:
            raise InputValidationError(
                f"Password length must be between {self.policy.min_length} and {self.policy.max_length}"
            )
        
        if category == PasswordCategory.PASSPHRASE:
            return self._generate_passphrase(length, strength)
        
        characters = self.character_lake.get_character_set(category)
        
        if strength == PasswordStrength.BASIC:
            generator = random.choice
        else:
            generator = secrets.choice
        
        attempts = 0
        max_attempts = 100
        
        while attempts < max_attempts:
            password = ''.join(generator(characters) for _ in range(length))
            if self.character_lake.validate_policy_compliance(password, category):
                return password
            attempts += 1
        
        raise PolicyViolationError(
            f"Could not generate password that meets policy requirements after {max_attempts} attempts"
        )
    
    def _generate_passphrase(self, word_count: int, strength: PasswordStrength) -> str:
        """
        Generate a memorable passphrase
        
        Args:
            word_count: Number of words in passphrase
            strength: Password strength level
            
        Returns:
            Generated passphrase string
        """
        if not self.wordlist:
            raise PasswordGeneratorError("Passphrase generation requires a wordlist")
        
        if strength == PasswordStrength.BASIC:
            generator = random.choice
        else:
            generator = secrets.choice
        
        words = [generator(self.wordlist) for _ in range(word_count)]
        
        # Apply some transformations for stronger passphrases
        if strength == PasswordStrength.STRONG:
            # Capitalize random words
            for i in range(len(words)):
                if secrets.randbelow(2):
                    words[i] = words[i].capitalize()
            
            # Add a digit
            words.append(secrets.choice(self.character_lake.digits))
        
        elif strength == PasswordStrength.PARANOID:
            # Capitalize all words
            words = [w.capitalize() for w in words]
            
            # Add digits and special characters
            words.append(secrets.choice(self.character_lake.digits))
            words.append(secrets.choice(self.character_lake.special))
            
            # Shuffle the components
            secrets.SystemRandom().shuffle(words)
        
        separator = secrets.choice(['-', '_', '.', ' ', '']) if strength != PasswordStrength.BASIC else ' '
        return separator.join(words)
    
    def generate_multiple(self, count: int, length: int, category: PasswordCategory,
                         strength: PasswordStrength = PasswordStrength.STRONG) -> List[str]:
        """
        Generate multiple passwords with the same specifications
        
        Args:
            count: Number of passwords to generate
            length: Desired password length
            category: Password category
            strength: Password strength level
            
        Returns:
            List of generated passwords
        """
        return [self.generate_password(length, category, strength) for _ in range(count)]

class PasswordCLI:
    """Command-line interface for password generator"""
    
    @staticmethod
    def run_interactive():
        """Run interactive password generation wizard"""
        try:
            print("Industrial Password Generator")
            print("=" * 40)
            
            # Get password category
            print("\nPassword Categories:")
            print("1. Alphanumeric (letters and numbers)")
            print("2. Complex (letters, numbers, and special characters)")
            print("3. Passphrase (memorable words)")
            
            category_choice = input("\nSelect category (1-3): ").strip()
            try:
                category = {
                    '1': PasswordCategory.ALPHANUMERIC,
                    '2': PasswordCategory.COMPLEX,
                    '3': PasswordCategory.PASSPHRASE
                }[category_choice]
            except KeyError:
                raise InputValidationError("Invalid category selection")
            
            # Get password length/word count
            prompt = "Enter password length: " if category != PasswordCategory.PASSPHRASE else "Enter number of words: "
            length = input(prompt).strip()
            try:
                length = int(length)
            except ValueError:
                raise InputValidationError("Invalid length - must be an integer")
            
            # Get strength level
            print("\nPassword Strength Levels:")
            print("1. Basic (faster, less secure)")
            print("2. Strong (recommended)")
            print("3. Paranoid (maximum security)")
            
            strength_choice = input("\nSelect strength level (1-3): ").strip()
            try:
                strength = {
                    '1': PasswordStrength.BASIC,
                    '2': PasswordStrength.STRONG,
                    '3': PasswordStrength.PARANOID
                }[strength_choice]
            except KeyError:
                raise InputValidationError("Invalid strength level selection")
            
            # Generate password
            generator = PasswordGenerator()
            password = generator.generate_password(length, category, strength)
            
            # Display results
            print("\nGenerated Password:")
            print(password)
            
            # Offer to save
            save = input("\nSave to file? (y/n): ").lower()
            if save == 'y':
                filename = input("Enter filename: ").strip()
                try:
                    with open(filename, 'w') as f:
                        json.dump({
                            'password': password,
                            'category': category.name,
                            'strength': strength.name,
                            'length': length
                        }, f, indent=2)
                    print(f"Password saved to {filename}")
                except IOError as e:
                    print(f"Failed to save file: {str(e)}", file=sys.stderr)
        
        except PasswordGeneratorError as e:
            print(f"\nError: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(0)
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)
    
    @staticmethod
    def run_from_args():
        """Run password generator from command-line arguments"""
        parser = argparse.ArgumentParser(description='Industrial Password Generator')
        parser.add_argument('--length', type=int, required=True, help='Password length or word count')
        parser.add_argument('--category', choices=['alphanumeric', 'complex', 'passphrase'], required=True)
        parser.add_argument('--strength', choices=['basic', 'strong', 'paranoid'], default='strong')
        parser.add_argument('--count', type=int, default=1, help='Number of passwords to generate')
        parser.add_argument('--output', help='Output file to save results')
        
        args = parser.parse_args()
        
        try:
            # Convert arguments to enums
            category = {
                'alphanumeric': PasswordCategory.ALPHANUMERIC,
                'complex': PasswordCategory.COMPLEX,
                'passphrase': PasswordCategory.PASSPHRASE
            }[args.category]
            
            strength = {
                'basic': PasswordStrength.BASIC,
                'strong': PasswordStrength.STRONG,
                'paranoid': PasswordStrength.PARANOID
            }[args.strength]
            
            # Generate passwords
            generator = PasswordGenerator()
            if args.count == 1:
                password = generator.generate_password(args.length, category, strength)
                result = {'password': password}
            else:
                passwords = generator.generate_multiple(args.count, args.length, category, strength)
                result = {'passwords': passwords}
            
            # Add metadata
            result.update({
                'category': args.category,
                'strength': args.strength,
                'length': args.length,
                'count': args.count
            })
            
            # Output results
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Results saved to {args.output}")
                except IOError as e:
                    print(f"Failed to save file: {str(e)}", file=sys.stderr)
                    sys.exit(1)
            else:
                print(json.dumps(result, indent=2))
        
        except PasswordGeneratorError as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    # Run in interactive mode if no args, otherwise parse args
    if len(sys.argv) == 1:
        PasswordCLI.run_interactive()
    else:
        PasswordCLI.run_from_args()
# 🔐 Password Generator

A highly configurable and secure password generator designed for individuals and organizations who require industrial-grade password policies and flexibility. It supports multiple password types including alphanumeric strings, complex combinations, and passphrases based on the [EFF large wordlist](https://www.eff.org/dice).

## 🚀 Features

* Alphanumeric, Complex, and Passphrase support
* Configurable password policies (length, character constraints, exclusions)
* Multiple strength levels: Basic, Strong, Paranoid
* Command-line interface and interactive mode
* Support for generating multiple passwords at once
* Optionally save passwords to a file in JSON format

---

## 📦 Installation

1. Clone the repository
2. (Optional) Create a virtual environment

3. Run the script directly:

   ```bash
   python password_generator.py
   ```

## 📖 Usage

### 🔧 Command-Line Mode

```bash
python password_generator.py \
    --length 16 \
    --category complex \
    --strength strong \
    --count 3 \
    --output generated_passwords.json
```

**Arguments:**

| Argument     | Description                                                          | Required |
| ------------ | -------------------------------------------------------------------- | -------- |
| `--length`   | Password length or number of words                                   | ✅        |
| `--category` | Password category: `alphanumeric`, `complex`, `passphrase`           | ✅        |
| `--strength` | Password strength: `basic`, `strong`, `paranoid` (default: `strong`) | ❌        |
| `--count`    | Number of passwords to generate (default: `1`)                       | ❌        |
| `--output`   | Path to output file to save the results                              | ❌        |

### 🧙 Interactive Mode

Run without any arguments:

```bash
python password_generator.py
```

You’ll be prompted to:

* Choose a category (Alphanumeric / Complex / Passphrase)
* Specify length or word count
* Select strength level
* Optionally save the result to a file

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is intended for educational and professional use. While it uses secure randomization practices (`secrets` module), it is **not a substitute for a vetted enterprise password management system** in highly regulated or security-critical environments. Use at your own risk.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

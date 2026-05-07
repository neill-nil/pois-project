# Minicrypt Clique Explorer & POIS Project

This project contains two major components for the CS8.401 Principles of Information Security course:

1. **Interactive Web Explorer (PA#0)** - A React-based web application to explore the Minicrypt clique and cryptographic reductions.
2. **Cryptographic Primitives (PA#1-PA#20)** - Pure Python implementations of core cryptographic primitives built from scratch without external libraries.

---

## 🌐 Running the Web Application (Interactive Explorer)

The web explorer provides an interactive UI to visualize foundations (AES/DLP), build primitives, and trace reduction algorithms step-by-step.

### Prerequisites

- [Node.js](https://nodejs.org/) (v14 or higher)
- [npm](https://www.npmjs.com/) (comes with Node.js)

### Steps to Run

1. Open a terminal and navigate to the project's web app directory from the main project folder:

   ```bash
   # First change to your project's root directory:
   cd /home/md-taufique-hussain/IIIT-H/Semester-2/POIS/Project/pois_prroject/pois_prroject

   # Then enter the web app directory:
   cd pa0_webapp
   ```

2. Install the required dependencies:

   ```bash
   npm install
   ```

3. Start the development server:

   ```bash
   npm start
   ```

4. The application should automatically open in your default web browser. If it doesn't, navigate to [http://localhost:3000](http://localhost:3000) manually.

---

## 🐍 Running the Python Cryptographic Scripts (PA#1 - PA#20)

The Python scripts are meant to be run directly in the terminal to watch their test/demo output logs.

### Prerequisites

- Python 3.7+ (No external cryptographic libraries are required per the no-library rule)

### Steps to Run

Navigate to the project root directory containing the `.py` files and execute them directly.

```bash
# Ensure you're in the correct folder:
cd /home/md-taufique-hussain/IIIT-H/Semester-2/POIS/Project/pois_prroject/pois_prroject

# Example: PA#12 (Textbook RSA + PKCS#1 v1.5)
python3 rsa.py

# PA#15: Digital Signatures
python3 signatures.py

# PA#20: Secure Multi-Party Computation
python3 mpc.py
```

To run all remaining tests in sequence, you can use:

```bash
for f in *.py; do echo "--- $f ---"; python3 $f; done
```

---

## ✅ Verification & Testing

To verify the correctness of the assignments and ensure that the "No-Library Rule" (no external crypto dependencies) is followed:

1. **Self-Contained Tests**: Every `.py` file contains comprehensive `if __name__ == "__main__":` blocks at the bottom. By running the scripts as shown above, you invoke these built-in test suites automatically.
2. **Reviewing Outputs**: Look for the checkmarks (`✓`), truth table assertions, and explicitly stated test outcomes (e.g., `Expected: 0 successes, Result: 0/20 forgeries succeeded`) generated in the terminal.
3. **Lineage Checks**: Modules like PA#17 (`cca_pkc.py`) and PA#20 (`mpc.py`) include automatic dependency/lineage traces to prove they route down to custom functions (e.g., `mod_exp` in `miller_rabin.py`).
4. **App Reactivity**: For the PA#0 WebApp, verification is done by checking the console logs directly underneath the panels or by opening the "Reduction Proof Summary" panel to verify the logical chaining behaves natively.

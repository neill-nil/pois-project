# Minicrypt Project: Programming Assignments 1 to 20

This document explains how to execute and test all 20 cryptography programming assignments from the command line.

## Prerequisites
- Python 3.x
- No external libraries require installation for the core algorithms (exclusively uses built-in `random`, `hashlib`, etc.)

## Instructions to Run the Scripts

You can run each script individually using `python3 <filename>`. Each script has a built-in `__main__` evaluation block that will print the setup, evaluation, and test checks automatically.

### PA#1 to PA#10: Symmetric Crypto & Hash Functions
Run these to test primitives like One-Way Functions, Block Ciphers, and MACs:

```bash
python3 Q1_owf_prg.py
python3 Q2_prf.py
python3 Q3_cpa_enc.py
python3 Q4_modes.py
python3 Q5_mac.py
python3 Q6_cca_enc.py
python3 Q7_merkle_damgard.py
python3 Q8_dlp_hash.py
python3 Q9_birthday_attack.py
python3 Q10_hmac_impl.py
```

### PA#11 to PA#16: Public Key Cryptography 
Run these to check primitives like Diffie-Hellman, RSA, and ElGamal:

```bash
python3 Q11_dh.py
python3 Q12_rsa.py
python3 Q13_miller_rabin.py
python3 Q14_crt.py
python3 Q15_signatures.py
python3 Q16_elgamal.py
```

### PA#17 to PA#20: Advanced Protocols & MPC
Run these to check complex constructions including CCA-secure PKC and Oblivious Transfer:

```bash
python3 Q17_cca_pkc.py
python3 Q18_ot.py
python3 Q19_secure_and.py
python3 Q20_mpc.py
```

## Running Everything at Once
If you want to run all 20 assignments sequentially to verify that everything passes without errors, you can run the following bash command in your terminal:

```bash
for i in {1..20}; do ls Q${i}_*.py | xargs python3; echo "----------------------"; done
```

## Web App Interactive Demos
A React front-end is additionally provided in the `pa0_webapp` directory to interactively demonstrate these concepts. To start the web app:
```bash
cd pa0_webapp
npm install
npm start
```

# Q17 to Q20 Demo Guide

Yeh file evaluator ke saamne Q17 se Q20 tak kya run karna hai, aur kya terminal pe dikhana hai, uske liye hai.

*(Note: Pehle ye lag raha tha web app `pa0_webapp` mein saare UI honge kyunki project PDF mein waisa diya hua tha. Par actually tumne PA#17 (CCA-PKC tamper) aur PA#20 (Millionaire) ka Demo **Terminal Scripts** ke andar hi likh diya hai! Isliye web page par dhoondhne ki zaroorat nahi hai, Evaluator ko seedhe bash terminal par Python script output hi dikhana hai!)*

## Kaise run karna hai

Project root folder me terminal kholo aur ye files ek-ek karke run karo:

```bash
python3 Q17_cca_pkc.py
python3 Q18_ot.py
python3 Q19_secure_and.py
python3 Q20_mpc.py
```

---

## Evaluator ko Python Terminal pe kya dikhana hai

### Q17 (PA#17) — CCA-Secure PKC Demo:
Terminal mein run karo: `python3 Q17_cca_pkc.py`
- Iski output mein line number `[3], [4], [5]` pe dhyaan se dikhao jahan likha hai:
  - `[3] Tampered ciphertext returns ⊥...` aur `Dec(tampered CE) = None` (iska matlab ciphertext ke saath chhed-chhaad ki gayi toh CCA-secure mechanism ne decrypt karna rok diya, jo WebApp mein button click jaisa hi proof hai).
  - Phir neeche "Malleability Attack Comparison" mein dikhao ki normal ElGamal pe attack ho gaya (`ATTACK SUCCEEDED`), lekin aapke CCA-PKC mein (`Attack blocked: True`).

### Q18 (PA#18) — Oblivious Transfer:
Terminal mein run karo: `python3 Q18_ot.py`
- Terminal output mein dikhao:
  - Receiver ko sirf apne pasand ka message milta hai (`Correctness Test (100 trials)` jiske `Errors: 0/100` aayenge).
  - Privacy Demo section jisme sender aur receiver ki privacy prove hoti hai (`Receiver cannot decrypt C_1 without the DL. ✓`).

### Q19 (PA#19) — Secure AND Gate:
Terminal mein run karo: `python3 Q19_secure_and.py`
- Terminal output mein dikhao:
  - Ki saari truth tables run hone par test paas hote hain.
  - Print hona chahiye: `All truth tables correct: True`.
  - Neeche `Privacy Demo` verify karta hai ki logs kisi bhi party ke input ko reveal nahi kar rahe hain.

### Q20 (PA#20) — All 2-Party Secure Computation (Millionaire's Demo):
Terminal mein run karo: `python3 Q20_mpc.py`
- File run karne ke baad terminal output mein **Millionaire's Problem** live evaluate hota hua dikhega:
  - `7 > 12? result=0 expected=0 ✓` (Proof for evaluator)
  - `3 + 5 mod 16 = result= 8 expected= 8 ✓` (Proof for evaluate)
  - **Full Call-Stack Trace**: Output mein check karo jahan yeh flow likha aayega `PA#19 -> PA#18 -> PA#16 -> PA#13`... evaluator ye dekh kar samajh jayega ki bina kisi bahari external library ke tumne pure core ko zero se likha hai!

---

## Short viva explanation

Agar evaluator pooche ki flow kya hai:
- Bol dena ki web app (React wala) assignment PA#0 (Minicrypt Clique Explorer) ka part hai. Lekin **PA#17 aur PA#20 ka jo validation demo tha ("Tampering", "Millionaires"), wo maine terminal based implementation rakhi hai.**
- Q17: Signature verify pehle hoti hai uske baad decryption hoti hai, taaki CCA attack pakda jaye.
- Q18: OT (Oblivious Transfer) 1-of-2 mechanism ke baare me batao.
- Q19: Secure AND ko banaya using Oblivious transfer. XOR / NOT dono ko seedhe build kiya locally.
- Q20: Secure gates lagakar koi bhi computation prove kiya. Call Stack proof sab kuch justify karta hai.

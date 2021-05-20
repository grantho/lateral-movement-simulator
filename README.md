# lateral-movement-simulator
A framework for synthesizing lateral movement login data.

attack_lib.py contains the end-to-end code for generating a DataFrame of attack logins that simulates a particular lateral movement attack path.

Invoke synthesize_attack(...) with a DataFrame of logins and an AttackPathConfig object that specifies the goals, stealthiness, and other parameters of the desired attack.

import os
import pickle
import subprocess

password = "admin123"  # Hardcoded password (Insecure)

# Dangerous use of eval
user_data = input("Enter your data: ")
result = eval(user_data)

# Insecure use of os.system
command = input("Enter a command to run: ")
os.system(command)

# Using exec to run dynamic code
code = "print('Hello from exec')"
exec(code)

# Pickle deserialization (dangerous if input is untrusted)
with open("data.pkl", "rb") as f:
    data = pickle.load(f)

# subprocess with potential input injection
cmd = input("Enter command: ")
subprocess.call(cmd, shell=True)

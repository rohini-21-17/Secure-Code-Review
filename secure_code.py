import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

# Analysis logic with detailed suggestions
def run_static_analysis(code):
    issues = []

    def add_issue(issue, recommendation, remediation):
        issues.append(f"🔍 {issue}\n💡 Recommendation: {recommendation}\n🔧 How to Fix: {remediation}\n{'-'*80}")

    if "eval(" in code:
        add_issue(
            "Use of 'eval()' detected.",
            "Avoid using 'eval()' to prevent arbitrary code execution.",
            "Use safe parsing methods like 'ast.literal_eval()' if parsing literals."
        )
    if "exec(" in code:
        add_issue(
            "Use of 'exec()' detected.",
            "Avoid using 'exec()', which can run arbitrary code.",
            "Use safer alternatives such as functions or if/else conditions."
        )
    if "import pickle" in code:
        add_issue(
            "Insecure 'pickle' module import found.",
            "'pickle' can execute arbitrary code if input is not trusted.",
            "Use 'json' for serializing data when security is a concern."
        )
    if "password" in code.lower() and "=" in code:
        add_issue(
            "Possible hardcoded password found.",
            "Do not store credentials directly in code.",
            "Use environment variables or external config files with secure access."
        )
    if "subprocess" in code:
        add_issue(
            "'subprocess' module used.",
            "Subprocess calls can be vulnerable to injection if user input is used.",
            "Use 'subprocess.run()' with argument list and `shell=False`."
        )
    if "os.system(" in code:
        add_issue(
            "Use of 'os.system()' detected.",
            "'os.system()' can lead to command injection vulnerabilities.",
            "Use 'subprocess.run()' with argument lists instead."
        )
    if "input(" in code and "int(" not in code and "str(" not in code:
        add_issue(
            "Direct use of 'input()' without validation.",
            "User input should always be validated/sanitized.",
            "Use proper validation methods to check and clean user input."
        )

    if not issues:
        issues.append("✅ No critical security issues detected. Keep following secure coding practices.")

    return "\n\n".join(issues)

# Load file content
def load_code_file():
    filepath = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
    if filepath:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as file:
                code = file.read()
                code_text.delete("1.0", tk.END)
                code_text.insert(tk.END, code)
        except Exception as e:
            result_text.insert(tk.END, f"Error loading file: {e}\n")

# Analyze button handler
def analyze_code():
    code = code_text.get("1.0", tk.END)
    result = run_static_analysis(code)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

# GUI Setup
root = tk.Tk()
root.title("Secure Code Review Tool")

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

load_button = tk.Button(button_frame, text="Load Python File", command=load_code_file, width=20)
load_button.grid(row=0, column=0, padx=5)

analyze_button = tk.Button(button_frame, text="Analyze Code", command=analyze_code, width=20)
analyze_button.grid(row=0, column=1, padx=5)

# Code input
code_label = tk.Label(root, text="Code to Review:")
code_label.pack()
code_text = ScrolledText(root, height=15, width=100)
code_text.pack(padx=10, pady=5)

# Result output
result_label = tk.Label(root, text="Security Issues, Recommendations & Remediation:")
result_label.pack()
result_text = ScrolledText(root, height=15, width=100, fg="darkred")
result_text.pack(padx=10, pady=5)

root.mainloop()



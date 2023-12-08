import re
import random
import tkinter as tk

def password_strength(password, min_length, max_length):
    length_error = len(password) < min_length or len(password) > max_length
    digit_error = not re.search(r"\d", password)
    lowercase_error = not re.search(r"[a-z]", password)
    uppercase_error = not re.search(r"[A-Z]", password)
    special_char_error = not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    score = 100 - (length_error + digit_error + lowercase_error + uppercase_error + special_char_error) * 20
    key_bit = len(password)
    password_ok = not (length_error or digit_error or lowercase_error or uppercase_error or special_char_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'lowercase_error': lowercase_error,
        'uppercase_error': uppercase_error,
        'special_char_error': special_char_error,
        'score': score,
        'key_bit': key_bit
    }

def generate_strong_password():
    suggestions = [
        "StrongPassword123!",
        "SecurePassw0rd!",
        "P@ssw0rd123",
        "MyStrongP@ss!",
        "SafePassword2022"
    ]
    return random.choice(suggestions)

def estimate_time_to_break(key_bit):
    attempts_per_second = 10**6  # Adjust this based on your assumptions
    seconds_per_minute = 60
    seconds_per_hour = 60 * seconds_per_minute
    seconds_per_day = 24 * seconds_per_hour

    time_to_break_seconds = 2**(key_bit - 1) / attempts_per_second
    time_to_break_days = time_to_break_seconds / seconds_per_day

    return time_to_break_days

def analyze_password():
    user_password = password_entry.get()
    min_length_val = int(min_length_entry.get())
    max_length_val = int(max_length_entry.get())
    result = password_strength(user_password, min_length_val, max_length_val)

    summary_message = "Analysis Summary:\n"

    if result['password_ok']:
        summary_message += "- The password is strong enough!\n"
    else:
        if result['length_error']:
            summary_message += f"- Password length should be between {min_length_val} and {max_length_val} characters. (❌)\n"
        else:
            summary_message += f"- Password length should be between {min_length_val} and {max_length_val} characters. (✔️)\n"

        if result['digit_error']:
            summary_message += "- Should contain at least one digit. (❌)\n"
        else:
            summary_message += "- Should contain at least one digit. (✔️)\n"

        if result['lowercase_error']:
            summary_message += "- Should contain at least one lowercase letter. (❌)\n"
        else:
            summary_message += "- Should contain at least one lowercase letter. (✔️)\n"

        if result['uppercase_error']:
            summary_message += "- Should contain at least one uppercase letter. (❌)\n"
        else:
            summary_message += "- Should contain at least one uppercase letter. (✔️)\n"

        if result['special_char_error']:
            summary_message += "- Should contain at least one special character. (❌)\n"
        else:
            summary_message += "- Should contain at least one special character. (✔️)\n"

        suggested_password = generate_strong_password()
        summary_message += f"\nSuggested strong password: {suggested_password}\n"

    summary_message += f"\nFinal password score: {result['score']}% - Equivalent key bit: {result['key_bit']} bits"

    if result['score'] < 40:
        summary_message += " - Weak Password (Bad)"
        result_color = "red"
        result_text = "Bad"
    elif 40 <= result['score'] <= 79:
        summary_message += " - Medium Strength Password (Medium)"
        result_color = "orange"
        result_text = "Medium"
    else:
        summary_message += " - Strong Password (Good)"
        result_color = "green"
        result_text = "Good"

    time_to_break_days = estimate_time_to_break(result['key_bit'])
    summary_message += f"\nEstimated time to break this password: {time_to_break_days:.2f} days"

    result_label.config(text=summary_message, fg=result_color)
    result_display.config(text=result_text, fg="white", font=("Helvetica", 16), bg=result_color)

def exit_application():
    root.destroy()

def clear_password():
    password_entry.delete(0, tk.END)
    min_length_entry.delete(0, tk.END)
    max_length_entry.delete(0, tk.END)
    enable_length_var.set(True)
    result_label.config(text="", fg="black")
    result_display.config(text="")

def toggle_length_inputs():
    min_length_entry.config(state=tk.NORMAL if enable_length_var.get() else tk.DISABLED)
    max_length_entry.config(state=tk.NORMAL if enable_length_var.get() else tk.DISABLED)

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_coordinate = (screen_width - width) // 2
    y_coordinate = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x_coordinate}+{y_coordinate}")

def center_content():
    for widget in [enable_length_check, min_length_label, min_length_entry,
                   max_length_label, max_length_entry, input_frame, password_label, password_entry,
                   analyze_button, clear_button, result_frame, result_label, result_display_frame,
                   result_display]:
        widget.pack(pady=5)

    created_by_label.pack(side=tk.BOTTOM, anchor=tk.SW)
    exit_button = tk.Button(root, text="Exit", command=exit_application)
    exit_button.pack(side=tk.BOTTOM, pady=10)

root = tk.Tk()
root.title("Password Strength Analyzer - Hamdi Barkallah")
root.geometry("750x500")

enable_length_var = tk.BooleanVar(value=True)
enable_length_check = tk.Checkbutton(root, text="Enable length editing", variable=enable_length_var, command=toggle_length_inputs)
enable_length_check.pack(pady=5)

min_length_label = tk.Label(root, text="Min Length:")
min_length_label.pack(pady=5)

min_length_entry = tk.Entry(root, state=tk.NORMAL)
min_length_entry.pack(pady=5)

max_length_label = tk.Label(root, text="Max Length:")
max_length_label.pack(pady=5)

max_length_entry = tk.Entry(root, state=tk.NORMAL)
max_length_entry.pack(pady=5)

input_frame = tk.Frame(root)
input_frame.pack(pady=10)

password_label = tk.Label(input_frame, text="Password:")
password_label.pack(side=tk.LEFT, padx=5)

password_entry = tk.Entry(input_frame, show="*")
password_entry.pack(side=tk.LEFT, padx=5)

analyze_button = tk.Button(input_frame, text="Analyze", command=analyze_password)
analyze_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(input_frame, text="Clear", command=clear_password)
clear_button.pack(side=tk.LEFT, padx=5)

result_frame = tk.Frame(root)
result_frame.pack(pady=10)

result_label = tk.Label(result_frame, text="", fg="black")
result_label.pack()

result_display_frame = tk.Frame(root)
result_display_frame.pack(pady=10)

result_display = tk.Label(result_display_frame, text="", font=("Helvetica", 16), justify=tk.CENTER)
result_display.pack(fill=tk.BOTH, expand=True)

created_by_label =tk.Label(root, text="Created By Hamdi Barkallah", font=("Helvetica", 10), fg="gray")

center_content()
root.mainloop()


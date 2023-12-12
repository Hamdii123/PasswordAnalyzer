import re
import random
import tkinter as tk
import math
import string

def check_password(password, min_length, max_length):
    length_error = len(password) < min_length or len(password) > max_length
    digit_error = not re.search(r"\d", password)
    lowercase_error = not re.search(r"[a-z]", password)
    uppercase_error = not re.search(r"[A-Z]", password)
    special_char_error = not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    score = 100 - (length_error + digit_error + lowercase_error + uppercase_error + special_char_error) * 20
    key_bit = len(password) * 8
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

def generate_strong_password(min_length, max_length):
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password_length = random.randint(min_length, max_length)
    suggested_password = ''.join(random.choice(all_characters) for _ in range(password_length))
    return suggested_password

def calculate_entropy(password):
    possible_characters = 0
    for char_set in [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]:
        possible_characters += len(set(password) & set(char_set))
    entropy = math.log2(possible_characters) * len(password)
    return entropy

def calculate_break_time(entropy):
    seconds_to_break = 2 ** entropy
    minutes_to_break = seconds_to_break / 60
    hours_to_break = minutes_to_break / 60
    days_to_break = hours_to_break / 24
    years_to_break = days_to_break / 365

    remaining_seconds = seconds_to_break % 60
    remaining_minutes = minutes_to_break % 60
    remaining_hours = hours_to_break % 24

    return (
        f"{int(years_to_break)} years, "
        f"{int(days_to_break % 365)} days, "
        f"{int(remaining_hours)} hours, "
        f"{int(remaining_minutes)} minutes, "
        f"{int(remaining_seconds)} seconds"
    )

def analyze_password():
    user_password = password_entry.get()
    min_length_val = int(min_length_entry.get())
    max_length_val = int(max_length_entry.get())
    result = check_password(user_password, min_length_val, max_length_val)

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

        entropy = calculate_entropy(user_password)
        time_to_break = calculate_break_time(entropy)
        summary_message += f"Estimated time to break this password: {time_to_break}"

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

    result_label.config(text=summary_message, fg=result_color)
    result_display.config(text=result_text, fg="white", font=("Helvetica", 16), bg=result_color)

def exit_application():
    root.destroy()

def clear_password():
    password_entry.delete(0, tk.END)
    min_length_entry.delete(0, tk.END)
    max_length_entry.delete(0, tk.END)
    enable_length_var.set(True)
    result_label.config(text="")
    result_display.config(text="")
    suggested_password_label.config(text="")
    

def toggle_length_inputs():
    min_length_entry.config(state=tk.NORMAL if enable_length_var.get() else tk.DISABLED)
    max_length_entry.config(state=tk.NORMAL if enable_length_var.get() else tk.DISABLED)

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_coordinate = (screen_width - width) // 2
    y_coordinate = (screen_height - height) // 2   
    window.geometry(f"{width}x{height}+{x_coordinate}+{y_coordinate}")

def generate_and_display_password():
    min_length_val = int(min_length_entry.get())
    max_length_val = int(max_length_entry.get())
    suggested_password = generate_strong_password(min_length_val, max_length_val)
    suggested_password_label.config(text=f"Suggested Password: {suggested_password}")

def center_content():
    for widget in [enable_length_check, min_length_label, min_length_entry,
                   max_length_label, max_length_entry, input_frame, password_label, password_entry,
                   analyze_button, clear_button, result_frame, result_label, result_display_frame,
                   result_display]:
        widget.pack(pady=5)

    exit_button = tk.Button(root, text="Exit", command=exit_application)
    exit_button.pack(side=tk.BOTTOM, pady=10)

root = tk.Tk()
root.title("Password Strength Analyzer - Hamdi Barkallah")
root.geometry("750x500")

enable_length_var = tk.BooleanVar(value=True)
enable_length_check = tk.Checkbutton(root, text="Enable length editing", variable=enable_length_var)
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

generate_password_button = tk.Button(root, text="Generate Suggested Password", command=generate_and_display_password)
generate_password_button.pack(side=tk.BOTTOM, pady=10)
suggested_password_label = tk.Label(root, text="", font=("Helvetica", 12), fg="black")
suggested_password_label.pack(side=tk.BOTTOM, pady=5)

center_content()
center_window(root, 750, 500)
root.mainloop()

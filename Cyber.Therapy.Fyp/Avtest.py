import tkinter as tk
from tkinter import filedialog

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            content = file.read()
            text_area.delete(1.0, tk.END)  # Clear previous content
            text_area.insert(tk.END, content)

# Create the main application window
app = tk.Tk()
app.title("Text File Viewer")

# Create a frame for the buttons
button_frame = tk.Frame(app)
button_frame.pack(pady=10)

# Create and place the "Open File" button
open_button = tk.Button(button_frame, text="Open File", command=open_file)
open_button.pack(side=tk.LEFT, padx=5)

# Create a text widget to display the file content
text_area = tk.Text(app, wrap=tk.WORD, width=40, height=10)
text_area.pack(padx=10, pady=5)

# Run the application
app.mainloop()
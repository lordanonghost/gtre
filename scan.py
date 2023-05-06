import tkinter as tk
from tkinter import messagebox
import requests
import whois

def check_vulnerabilities():
    try:
        # Get the URL entered by the user
        url = url_entry.get()

        # Build the URL for vulnerability scanning
        vulnerability_url = f"https://www.example.com/vulnerability-scan?url={url}"

        # Send a GET request to check vulnerabilities
        response = requests.get(vulnerability_url)

        # Display the vulnerability scan results in a message box
        messagebox.showinfo("Vulnerability Check", response.text)
    except requests.exceptions.RequestException:
        messagebox.showerror("Error", "Failed to perform vulnerability check.")

def view_robots_txt():
    try:
        # Get the URL entered by the user
        url = url_entry.get()

        # Build the URL for accessing robots.txt
        robots_url = f"{url}/robots.txt"

        # Send a GET request to retrieve robots.txt
        response = requests.get(robots_url)

        # Display the contents of robots.txt in a message box
        messagebox.showinfo("Robots.txt", response.text)
    except requests.exceptions.RequestException:
        messagebox.showerror("Error", "Failed to retrieve robots.txt.")

def perform_whois_lookup():
    try:
        # Get the domain entered by the user
        domain = domain_entry.get()

        # Perform a WHOIS lookup
        w = whois.whois(domain)

        # Display the WHOIS information in a message box
        messagebox.showinfo("WHOIS Lookup", f"WHOIS information for {domain}:\n\n{w}")
    except whois.parser.PywhoisError:
        messagebox.showerror("Error", "Failed to perform WHOIS lookup.")

# Create the main window
window = tk.Tk()
window.title("Web Vulnerability Check, Robots.txt, and WHOIS Lookup Tool")

# Create a label and entry for entering the URL
url_label = tk.Label(window, text="URL:")
url_label.pack()
url_entry = tk.Entry(window, width=50)
url_entry.pack()

# Create a button for checking vulnerabilities
vulnerability_check_button = tk.Button(window, text="Check Vulnerabilities", command=check_vulnerabilities)
vulnerability_check_button.pack()

# Create a button for viewing robots.txt
robots_txt_button = tk.Button(window, text="View robots.txt", command=view_robots_txt)
robots_txt_button.pack()

# Create a label and entry for entering the domain
domain_label = tk.Label(window, text="Domain:")
domain_label.pack()
domain_entry = tk.Entry(window, width=50)
domain_entry.pack()

# Create a button for performing WHOIS lookup
whois_lookup_button = tk.Button(window, text="Perform WHOIS Lookup", command=perform_whois_lookup)
whois_lookup_button.pack()

# Start the GUI main loop
window.mainloop()
import tkinter as tk
from tkinter import messagebox
import requests
import base64
import socket  # Importing socket for IP resolution

# Your API key from VirusTotal (make sure to keep this secret)
API_KEY = '350373a564c31a904ce25f2e5911e36e15afe02d15fb94497bc89b2ccb61060a'

# Function to check the URL using VirusTotal
def check_url():
    url_to_check = url_entry.get()  # Get the URL from the input field
    
    if not url_to_check:
        messagebox.showerror("Input Error", "Please enter a URL.")
        return
    
    # Check if the URL is potentially malicious
    if url_to_check.startswith("http://"):
        messagebox.showwarning("Warning", "The URL is potentially malicious (HTTP).")
        malicious_level = "High"
    elif url_to_check.startswith("https://"):
        malicious_level = "Low"
    else:
        messagebox.showerror("Input Error", "Please enter a valid URL starting with http:// or https://.")
        return

    try:
        # Base64 encode the URL and remove any padding (=)
        encoded_url = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'

        # Headers for the API request (including your API key)
        headers = {
            'x-apikey': API_KEY
        }

        # Make a GET request to the API
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            json_data = response.json()
            
            # Check if the JSON data contains scan data
            if 'data' in json_data:
                result = json_data['data']
                scan_results = result.get('attributes', {}).get('last_analysis_stats', 'No analysis available')
                
                # Resolve the IP address of the domain
                domain = url_to_check.split("//")[-1].split("/")[0]  # Extract domain from URL
                ip_address = socket.gethostbyname(domain)  # Get IP address
                
                # Display the result in a message box
                messagebox.showinfo("VirusTotal Report", f"Scan results: {scan_results}\nMalicious Level: {malicious_level}\nIP Address: {ip_address}")
            else:
                messagebox.showerror("Error", "No scan data found.")
        else:
            messagebox.showerror("Error", f"Error: {response.status_code} - {response.text}")
    
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Request Error", f"An error occurred: {e}")
    except socket.gaierror:
        messagebox.showerror("Error", "Could not resolve the domain to an IP address.")

# Create the main application window
root = tk.Tk()
root.title("VirusTotal URL Checker")
root.geometry("400x200")

# Create a label, entry field, and button
url_label = tk.Label(root, text="Enter URL to check:")
url_label.pack(pady=10)

url_entry = tk.Entry(root, width=40)
url_entry.pack(pady=5)

check_button = tk.Button(root, text="Check URL", command=check_url)
check_button.pack(pady=20)

# Run the GUI application
root.mainloop()
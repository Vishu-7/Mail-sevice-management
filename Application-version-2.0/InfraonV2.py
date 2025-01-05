import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle
import os
import base64
import email
from email.header import decode_header
from datetime import datetime, timedelta
import pytz
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from fpdf import FPDF
import io
from PIL import Image
import numpy as np
import tempfile
import json

class EmailClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EmailAuditPro")
        self.root.geometry("1200x700")
        self.root.iconbitmap("Mail.ico")

        # Initialize variables
        self.service = None
        # Define SCOPES as class attribute
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
        
        self.email_categories = {
            'Support Requests': 0,
            'Bug Reports': 0,
            'Feature Requests': 0,
            'General Inquiries': 0,
            'Others': 0
        }
        
        # Center the window
        self.center_window()

        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[20, 10])

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root, style='TNotebook')
        self.notebook.pack(fill="both", expand=True)

        # Create tabs
        self.login_tab = ttk.Frame(self.notebook)
        self.mail_audit_tab = ttk.Frame(self.notebook)
        self.view_chart_tab = ttk.Frame(self.notebook)
        self.report_tab = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.mail_audit_tab, text="Mail Audit")
        self.notebook.add(self.view_chart_tab, text="View Chart")
        self.notebook.add(self.report_tab, text="Audit Report")

        # Build all tabs
        self.build_login_tab()
        self.build_mail_audit_tab()
        self.build_view_chart_tab()
        self.build_report_tab()

        # Initialize counters
        self.answered_count = 0
        self.unanswered_count = 0

    def load_json_file(self):
        """Load the credentials JSON file"""
        self.credentials_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if self.credentials_path:
            try:
                with open(self.credentials_path, 'r') as json_file:
                    self.creds_data = json.load(json_file)
                    self.authenticate()  # Call authenticate directly after loading JSON
                    messagebox.showinfo("Success", "OAuth JSON file loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load JSON file: {str(e)}")    




    def authenticate(self):
        """Authenticate with Gmail API"""
        try:
            creds = None
            # Check if token file exists
            if os.path.exists('token.json'):
                creds = Credentials.from_authorized_user_file('token.json', self.SCOPES)

            # If no valid credentials available, let user log in
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    # Use the loaded credentials file directly
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, self.SCOPES)
                    creds = flow.run_local_server(port=0)

                # Save the credentials for the next run
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())

            # Create Gmail API service
            self.service = build('gmail', 'v1', credentials=creds)
            self.notebook.select(self.mail_audit_tab)
            messagebox.showinfo("Success", "Successfully authenticated with Gmail!")

        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {str(e)}")


    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    def build_login_tab(self):
        login_frame = ttk.Frame(self.login_tab)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(login_frame, text="Gmail API Authentication", font=("Helvetica", 16, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 20))

        ttk.Label(login_frame, text="Upload JSON File for User Switching:").grid(row=1, column=0, padx=5, pady=5)
        self.json_file_button = ttk.Button(login_frame, text="Upload JSON", command=self.load_json_file)
        self.json_file_button.grid(row=1, column=1, padx=5, pady=5)

        self.login_button = ttk.Button(login_frame, text="Authenticate with Google", command=self.authenticate)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=20)




    def fetch_emails(self):
        """Fetch emails using Gmail API"""
        if not self.service:
            messagebox.showerror("Error", "Please authenticate first")
            return

        try:
            selected_date = self.date_entry.get()
            
            # Validate date format
            if not re.match(r'^\d{2}-\d{2}-\d{4}$', selected_date):
                messagebox.showerror("Error", "Please enter date in DD-MM-YYYY format")
                return

            # Convert DD-MM-YYYY to YYYY-MM-DD for Gmail API query
            date_obj = datetime.strptime(selected_date, '%d-%m-%Y')
            query_date = date_obj.strftime('%Y-%m-%d')
            query = f'after:{query_date} before:{(date_obj + timedelta(days=1)).strftime("%Y-%m-%d")} in:inbox'

            # Clear existing items
            for item in self.mail_audit_tree.get_children():
                self.mail_audit_tree.delete(item)

            # Reset categories and counters
            for category in self.email_categories:
                self.email_categories[category] = 0
            #self.answered_count = 0
            self.unanswered_count = 0

            
            # Fetch threads instead of messages
            results = self.service.users().threads().list(userId='me', q=query).execute()
            threads = results.get('threads', [])

            if not threads:
                messagebox.showinfo("Information", "No emails found for the selected date")
                self.update_chart_tab()
                self.update_preview()
                return

            # Process threads
            self.process_threads(threads)
            
            # Update views
            self.update_chart_tab()
            self.update_preview()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch emails: {str(e)}")









    def process_threads(self, threads):
        """Process email threads fetched from Gmail API"""
        blacklisted_senders = {'support.infraon@everestims.com', 'support.infraondesk@everestims.com'}
        unique_senders = set()
        
        idx = 1  # Initialize counter for displayed messages
        
        for thread in threads:
            try:
                # Get thread details
                thread_details = self.service.users().threads().get(userId='me', id=thread['id']).execute()
                messages = thread_details.get('messages', [])
                
                if not messages:
                    continue

                # Get the latest message in thread
                latest_message = messages[-1]
                
                # Extract headers
                headers = latest_message['payload']['headers']
                from_addr = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'No Sender')
                
                # Skip blacklisted senders
                if from_addr in blacklisted_senders:
                    continue
                    
                # Skip if sender already processed
                if from_addr in unique_senders:
                    continue
                    
                # Determine state (answered/unanswered)
                state = "Answered" if len(messages) > 1 else "Unanswered"
                
                # Process all messages (both answered and unanswered)
                unique_senders.add(from_addr)
                
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'No Date')
                
                # Convert date to IST
                date_ist = self.convert_to_ist(date)
                
                # Update counters
                if state == "Answered":
                    self.answered_count += 1
                    continue
                else:
                    self.unanswered_count += 1

                # Create mail info
                mail_info = f"From: {from_addr}\nSubject: {subject}\nDate: {date_ist}"
                
                # Add to treeview all emails
                self.mail_audit_tree.insert("", "end", values=(idx, mail_info, state))
                
                # Categorize email
                category = self.categorize_email(subject, self.get_email_body(latest_message))
                self.email_categories[category] += 1
                
                idx += 1  # Increment counter for displayed messages

            except Exception as e:
                print(f"Error processing thread {idx}: {str(e)}")
                continue

        # Apply row colors
        self.apply_row_colors()













    def get_email_body(self, msg):
        """Extract email body from Gmail API message"""
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body_bytes = base64.urlsafe_b64decode(part['body']['data'])
                    return body_bytes.decode()
        elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            body_bytes = base64.urlsafe_b64decode(msg['payload']['body']['data'])
            return body_bytes.decode()
        return ""

   
















    def apply_row_colors(self):
        """Apply alternating row colors to treeview"""
        for i, item in enumerate(self.mail_audit_tree.get_children()):
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.mail_audit_tree.item(item, tags=(tag,))

        self.mail_audit_tree.tag_configure("evenrow", background="#f2f2f2")
        self.mail_audit_tree.tag_configure("oddrow", background="#ffffff")

    def build_mail_audit_tab(self):
        # Filter frame
        filter_frame = ttk.Frame(self.mail_audit_tab)
        filter_frame.pack(fill="x", padx=10, pady=10)

        # Get current date in IST
        ist_tz = pytz.timezone("Asia/Kolkata")
        current_date_ist = datetime.now(ist_tz).strftime("%d-%m-%Y")

        # Single Date input with current date as default
        ttk.Label(filter_frame, text="Select Date (DD-MM-YYYY):").pack(side="left", padx=5)
        self.date_entry = ttk.Entry(filter_frame, width=20)
        self.date_entry.pack(side="left", padx=5)
        self.date_entry.insert(0, current_date_ist)

        self.fetch_button = ttk.Button(filter_frame, text="Fetch Emails", command=self.fetch_emails)
        self.fetch_button.pack(side="left", padx=10)

        # Treeview style
        style = ttk.Style()
        style.configure("Custom.Treeview", rowheight=100, font=("Helvetica", 12))
        style.configure("Custom.Treeview.Heading", font=("Helvetica", 14, "bold"))

        # Create Treeview
        columns = ("Sl. No", "Mail-Info", "State")
        self.mail_audit_tree = ttk.Treeview(
            self.mail_audit_tab,
            columns=columns,
            show="headings",
            style="Custom.Treeview"
        )

        # Configure columns
        self.mail_audit_tree.heading("Sl. No", text="Sl. No")
        self.mail_audit_tree.column("Sl. No", width=50, anchor="center")

        self.mail_audit_tree.heading("Mail-Info", text="Mail-Info")
        self.mail_audit_tree.column("Mail-Info", width=600, anchor="w")

        self.mail_audit_tree.heading("State", text="State")
        self.mail_audit_tree.column("State", width=100, anchor="center")

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.mail_audit_tab, orient="vertical", command=self.mail_audit_tree.yview)
        self.mail_audit_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.mail_audit_tree.pack(fill="both", expand=True, padx=30, pady=20)
        scrollbar.pack(side="right", fill="y")

    def build_view_chart_tab(self):
        self.chart_frame = ttk.Frame(self.view_chart_tab)
        self.chart_frame.pack(fill="both", expand=True, padx=20, pady=20)

    def build_report_tab(self):
        # Main frame
        report_frame = ttk.Frame(self.report_tab)
        report_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Preview frame
        preview_frame = ttk.LabelFrame(report_frame, text="Report Preview")
        preview_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Preview text widget
        self.preview_text = tk.Text(preview_frame, height=20, width=80)
        self.preview_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Download options frame
        download_frame = ttk.LabelFrame(report_frame, text="Download Options")
        download_frame.pack(fill="x", padx=10, pady=10)

        # Export buttons
        ttk.Button(download_frame, text="Export as PDF", 
                  command=lambda: self.export_report("pdf")).pack(side="left", padx=5, pady=5)
        ttk.Button(download_frame, text="Export as CSV", 
                  command=lambda: self.export_report("csv")).pack(side="left", padx=5, pady=5)
        ttk.Button(download_frame, text="Export as Excel", 
                  command=lambda: self.export_report("xlsx")).pack(side="left", padx=5, pady=5)

    def update_chart_tab(self):
        """Update the pie chart visualization"""
        try:
            for widget in self.chart_frame.winfo_children():
                widget.destroy()

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

            # Response status chart
            labels1 = ["Answered", "Unanswered"]
            sizes1 = [self.answered_count, self.unanswered_count]
            
            if sum(sizes1) == 0:
                ax1.text(0.5, 0.5, 'No data available', 
                        horizontalalignment='center',
                        verticalalignment='center')
                ax2.text(0.5, 0.5, 'No data available', 
                        horizontalalignment='center',
                        verticalalignment='center')
            else:
                colors1 = ["#4CAF50", "#FF5722"]
                ax1.pie(sizes1, labels=labels1, autopct="%1.1f%%", startangle=140, colors=colors1)
                ax1.set_title("Response Status Distribution")

                # Categories chart
                labels2 = list(self.email_categories.keys())
                sizes2 = list(self.email_categories.values())
                if sum(sizes2) > 0:
                    ax2.pie(sizes2, labels=labels2, autopct="%1.1f%%", startangle=90)
                    ax2.set_title("Email Categories Distribution")

            plt.tight_layout()
            
            chart_canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            chart_canvas.draw()
            chart_canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            messagebox.showerror("Error", "Failed to update charts")

    def update_preview(self):
        """Update the report preview"""
        try:
            report_data = self.generate_report_data()
            
            self.preview_text.delete(1.0, tk.END)
            
            # Add report content
            self.preview_text.insert(tk.END, "EMAIL AUDIT REPORT\n")
            self.preview_text.insert(tk.END, "=" * 50 + "\n\n")
            
            if sum(report_data['categories'].values()) == 0:
                self.preview_text.insert(tk.END, "No emails found for the selected date range.\n")
                return
                
            # Summary section
            self.preview_text.insert(tk.END, "SUMMARY\n")
            self.preview_text.insert(tk.END, "-" * 20 + "\n")
            for key, value in report_data['summary'].items():
                self.preview_text.insert(tk.END, f"{key}: {value}\n")
            
            # Categories section
            self.preview_text.insert(tk.END, "\nEMAIL CATEGORIES\n")
            self.preview_text.insert(tk.END, "-" * 20 + "\n")
            for category, count in report_data['categories'].items():
                self.preview_text.insert(tk.END, f"{category}: {count}\n")
            
            # Detailed emails section
            if report_data['emails']:
                self.preview_text.insert(tk.END, "\nDETAILED EMAIL LIST\n")
                self.preview_text.insert(tk.END, "-" * 20 + "\n")
                for email in report_data['emails']:
                    self.preview_text.insert(tk.END, f"\nEmail #{email['Sl. No']}\n")
                    self.preview_text.insert(tk.END, f"{email['Mail-Info']}\n")
                    self.preview_text.insert(tk.END, f"Status: {email['State']}\n")
                    self.preview_text.insert(tk.END, "-" * 40 + "\n")

        except Exception as e:
            messagebox.showerror("Error", "Failed to update preview")

    def generate_report_data(self):
        """Generate comprehensive report data"""
        total_emails = self.answered_count + self.unanswered_count
        response_rate = (self.answered_count / total_emails * 100) if total_emails > 0 else 0
        
        report_data = {
            'summary': {
                'Total Emails': total_emails,
                'Answered Emails': self.answered_count,
                'Unanswered Emails': self.unanswered_count,
                'Response Rate': f"{response_rate:.2f}%"
            },
            'categories': self.email_categories,
            'emails': []
        }

        # Collect email details
        for item in self.mail_audit_tree.get_children():
            values = self.mail_audit_tree.item(item)['values']
            report_data['emails'].append({
                'Sl. No': values[0],
                'Mail-Info': values[1],
                'State': values[2]
            })

        return report_data

    def categorize_email(self, subject, body):
        """Categorize email based on subject and content"""
        subject_lower = subject.lower()
        body_lower = body.lower() if body else ""
        
        if any(word in subject_lower or word in body_lower 
               for word in ['support', 'help', 'assist']):
            return 'Support Requests'
        elif any(word in subject_lower or word in body_lower 
                for word in ['bug', 'error', 'issue', 'problem']):
            return 'Bug Reports'
        elif any(word in subject_lower or word in body_lower 
                for word in ['feature', 'enhancement', 'request']):
            return 'Feature Requests'
        elif any(word in subject_lower or word in body_lower 
                for word in ['question', 'inquiry', 'info']):
            return 'General Inquiries'
        else:
            return 'Others'

    def convert_to_ist(self, date_str):
        """Convert email date to IST timezone"""
        try:
            email_date = email.utils.parsedate_to_datetime(date_str)
            ist_tz = pytz.timezone("Asia/Kolkata")
            return email_date.astimezone(ist_tz).strftime("%d-%b-%Y %H:%M:%S")
        except (TypeError, ValueError):
            return date_str

    def export_report(self, format_type):
        """Export the report in the specified format"""
        report_data = self.generate_report_data()
        
        if format_type == "pdf":
            self.export_pdf(report_data)
        elif format_type == "csv":
            self.export_csv(report_data)
        elif format_type == "xlsx":
            self.export_excel(report_data)

    def export_pdf(self, report_data):
        """Export report as PDF"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")]
        )
        
        if file_path:
            try:
                pdf = FPDF()
                pdf.add_page()
                
                # Title
                pdf.set_font("Arial", "B", 16)
                pdf.cell(0, 10, "Email Audit Report", ln=True, align="C")
                pdf.ln(10)
                
                # Summary
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Summary", ln=True)
                pdf.set_font("Arial", "", 12)
                for key, value in report_data['summary'].items():
                    pdf.cell(0, 10, f"{key}: {value}", ln=True)
                pdf.ln(5)
                
                # Categories
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Email Categories", ln=True)
                pdf.set_font("Arial", "", 12)
                for category, count in report_data['categories'].items():
                    pdf.cell(0, 10, f"{category}: {count}", ln=True)
                
                # Save the PDF
                pdf.output(file_path)
                messagebox.showinfo("Success", "PDF report has been generated!")
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate PDF: {str(e)}")

    def export_csv(self, report_data):
        """Export report as CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if file_path:
            try:
                df = pd.DataFrame(report_data['emails'])
                df.to_csv(file_path, index=False)
                messagebox.showinfo("Success", "CSV report has been generated!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate CSV: {str(e)}")

    def export_excel(self, report_data):
        """Export report as Excel"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")]
        )
        
        if file_path:
            try:
                with pd.ExcelWriter(file_path) as writer:
                    # Summary sheet
                    pd.DataFrame(list(report_data['summary'].items()),
                               columns=['Metric', 'Value']).to_excel(writer, 
                                                                   sheet_name='Summary',
                                                                   index=False)
                    
                    # Categories sheet
                    pd.DataFrame(list(report_data['categories'].items()),
                               columns=['Category', 'Count']).to_excel(writer,
                                                                     sheet_name='Categories',
                                                                     index=False)
                    
                    # Detailed emails sheet
                    pd.DataFrame(report_data['emails']).to_excel(writer,
                                                               sheet_name='Detailed Emails',
                                                               index=False)
                
                messagebox.showinfo("Success", "Excel report has been generated!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate Excel: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailClientApp(root)
    root.mainloop()
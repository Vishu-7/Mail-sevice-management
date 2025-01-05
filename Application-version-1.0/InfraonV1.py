import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import imaplib
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
import os
import tempfile

class EmailClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EmailAudit")
        self.root.geometry("1200x700")
        self.root.iconbitmap("Mail.ico")

        # Initialize variables
        self.mail = None
        self.email_categories = {
            'Support Requests': 0,
            'Bug Reports': 0,
            'Feature Requests': 0,
            'General Inquiries': 0,
            'Others': 0
        }

        # Default email and password
        self.default_email = "infraonsupport@everestims.com"
        self.default_password = "itppfwrrcvrcbhae"

        # Center the window
        self.center_window()


        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[20, 10])




        # Create notebook for tabs
        self.notebook = ttk.Notebook(root,style='TNotebook')
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

        # Login header
        ttk.Label(login_frame, text="Email Login", font=("Helvetica", 16, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 20))

        # Email field
        ttk.Label(login_frame, text="Email:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.email_entry = ttk.Entry(login_frame, width=30)
        self.email_entry.insert(0, self.default_email)
        self.email_entry.grid(row=1, column=1, padx=10, pady=10)

        # Password field
        ttk.Label(login_frame, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.password_entry.insert(0, self.default_password)
        self.password_entry.grid(row=2, column=1, padx=10, pady=10)

        # Login button
        self.login_button = ttk.Button(login_frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=20)






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
        self.date_entry.insert(0, current_date_ist)  # Set current IST date as default

        self.fetch_button = ttk.Button(filter_frame, text="Fetch Emails", command=self.fetch_emails)
        self.fetch_button.pack(side="left", padx=10)

        # Rest of the existing code remains the same
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

    def login(self):
        self.email = self.email_entry.get()
        self.password = self.password_entry.get()

        if not self.email or not self.password:
            messagebox.showerror("Error", "Email and password are required.")
            return

        try:
            self.mail = imaplib.IMAP4_SSL("imap.gmail.com")
            self.mail.login(self.email, self.password)
            self.notebook.select(self.mail_audit_tab)
        except imaplib.IMAP4.error:
            messagebox.showerror("Error", "Invalid credentials. Please try again.")

    






    def fetch_emails(self):
        """Fetch emails from IMAP server with improved filtering and processing"""
        if not self.mail:
            messagebox.showerror("Error", "Please login first.")
            return

        try:
            # Get and validate date from entry field
            selected_date = self.date_entry.get()
            if not re.match(r'^\d{2}-\d{2}-\d{4}$', selected_date):
                messagebox.showerror("Error", "Please enter date in DD-MM-YYYY format")
                return

            # Convert selected date to datetime object
            selected_datetime = datetime.strptime(selected_date, "%d-%m-%Y")
            
            # Create IMAP format dates
            # IMAP requires dates in DD-MMM-YYYY format with English month abbreviations
            search_date = selected_datetime.strftime("%d-%b-%Y").upper()
            next_date = (selected_datetime + timedelta(days=1)).strftime("%d-%b-%Y").upper()

            # Reset counters and categories
            self.email_categories = {key: 0 for key in self.email_categories}
            self.answered_count = 0
            self.unanswered_count = 0

            # Clear existing items in treeview
            for item in self.mail_audit_tree.get_children():
                self.mail_audit_tree.delete(item)

            # Select inbox
            self.mail.select("inbox")
            
            # Use ON date criteria instead of SINCE and BEFORE
            # Format: (ON "DD-MMM-YYYY")
            search_criteria = f'(ON "{search_date}")'
            
            # For debugging
            print(f"Searching with criteria: {search_criteria}")
            
            status, messages = self.mail.search(None, search_criteria)
            
            if status != "OK":
                print(f"Search failed with status: {status}")
                messagebox.showerror("Error", "Failed to search emails")
                return

            if not messages[0]:
                print("No messages found")
                messagebox.showinfo("Information", "No emails found for the selected date")
                self.update_chart_tab()
                self.update_preview()
                return

            # Process messages
            message_nums = messages[0].split()
            if message_nums:
                print(f"Found {len(message_nums)} messages")
                self.process_emails(message_nums)
            
            # Update visualizations
            self.update_chart_tab()
            self.update_preview()

        except Exception as e:
            print(f"Error details: {str(e)}")
            messagebox.showerror("Error", f"Failed to fetch emails: {str(e)}")










    def process_emails(self, message_nums):
        """Process emails with improved thread handling and categorization"""
        try:
            # Blacklist for filtering out certain email addresses
            blacklisted_senders = {
                'support.infraon@everestims.com', 
                'support.infraondesk@everestims.com'
            }
            
            # Track unique threads and senders
            email_threads = {}
            processed_senders = set()
            
            # First pass: collect thread information
            for num in message_nums:
                status, data = self.mail.fetch(num, "(RFC822)")
                if status != "OK":
                    continue

                msg = email.message_from_bytes(data[0][1])
                from_addr = msg["From"]
                
                # Skip blacklisted senders
                if any(blocked in from_addr for blocked in blacklisted_senders):
                    continue

                message_id = msg.get("Message-ID", "")
                references = msg.get("References", "").split() + [msg.get("In-Reply-To", "")]
                
                # Convert date to IST
                date_str = msg["Date"]
                try:
                    email_date = email.utils.parsedate_to_datetime(date_str)
                    ist_tz = pytz.timezone("Asia/Kolkata")
                    email_date = email_date.astimezone(ist_tz)
                except:
                    email_date = datetime.min

                email_threads[message_id] = {
                    'msg': msg,
                    'references': references,
                    'has_reply': False,
                    'date': email_date,
                    'from': from_addr
                }
                
                # Mark referenced messages as having replies
                for ref in references:
                    if ref in email_threads:
                        email_threads[ref]['has_reply'] = True

            # Sort threads by date
            sorted_threads = sorted(
                email_threads.items(), 
                key=lambda x: x[1]['date'],
                reverse=True
            )

            # Second pass: display and categorize emails
            idx = 1
            for message_id, thread_info in sorted_threads:
                msg = thread_info['msg']
                from_addr = thread_info['from']
                
                # Skip if sender already processed
                if from_addr in processed_senders:
                    continue
                    
                processed_senders.add(from_addr)
                
                # Get email details
                subject = self.decode_subject(msg["Subject"])
                date = self.convert_to_ist(msg["Date"])
                
                # Get email body and categorize
                body = self.get_email_body(msg)
                category = self.categorize_email(subject, body)
                self.email_categories[category] += 1

                # Determine email state
                state = self.determine_email_state(msg, thread_info['has_reply'], email_threads)
                
                # Update counters
                if state == "Answered":
                    self.answered_count += 1
                    continue
                else:
                    self.unanswered_count += 1

                
                # Create and add mail info to treeview
                mail_info = f"From: {from_addr}\nSubject: {subject}\nDate: {date}"
                self.mail_audit_tree.insert("", "end", values=(idx, mail_info, state))
                idx += 1

            # Apply alternating row colors
            self.apply_row_colors()

        except Exception as e:
            print(f"Error processing emails: {str(e)}")
            raise











    def get_email_body(self, msg):
        """Extract email body from message"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode()
                        break
                    except:
                        continue
        else:
            try:
                body = msg.get_payload(decode=True).decode()
            except:
                pass
        return body

    def apply_row_colors(self):
        """Apply alternating row colors to treeview"""
        for i, item in enumerate(self.mail_audit_tree.get_children()):
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.mail_audit_tree.item(item, tags=(tag,))

        self.mail_audit_tree.tag_configure("evenrow", background="#f2f2f2")
        self.mail_audit_tree.tag_configure("oddrow", background="#ffffff")







    def update_chart_tab(self):
        """Update the pie chart visualization"""
        try:
            for widget in self.chart_frame.winfo_children():
                widget.destroy()

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

            # Response status chart
            labels1 = ["Answered", "Unanswered"]
            sizes1 = [self.answered_count, self.unanswered_count]
            
            # Check if there's any data
            if sum(sizes1) == 0:
                # Display empty charts with message
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
                if sum(sizes2) > 0:  # Only create pie if there's data
                    ax2.pie(sizes2, labels=labels2, autopct="%1.1f%%", startangle=90)
                    ax2.set_title("Email Categories Distribution")

            plt.tight_layout()
            
            chart_canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            chart_canvas.draw()
            chart_canvas.get_tk_widget().pack(fill="both", expand=True)

        except Exception as e:
            print(f"Chart update error: {str(e)}")  # For debugging
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
            print(f"Preview update error: {str(e)}")  # For debugging
            messagebox.showerror("Error", "Failed to update preview")








    def generate_report_data(self):
        """Generate comprehensive report data"""
        total_emails = self.answered_count + self.unanswered_count
        response_rate = (self.answered_count / total_emails * 100) if total_emails > 0 else 0
        
        # Calculate average response time (if available)
        avg_response_time = self.calculate_average_response_time()
        
        report_data = {
            'summary': {
                'Total Emails': total_emails,
                'Answered Emails': self.answered_count,
                'Unanswered Emails': self.unanswered_count,
                'Response Rate': f"{response_rate:.2f}%",
                'Average Response Time': avg_response_time
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

    def calculate_average_response_time(self):
        """Calculate average response time for answered emails"""
        try:
            response_times = []
            for item in self.mail_audit_tree.get_children():
                values = self.mail_audit_tree.item(item)['values']
                if values[2] == "Answered":
                    # Extract dates from mail info
                    mail_info = values[1]
                    date_match = re.search(r'Date: (.+)$', mail_info, re.MULTILINE)
                    if date_match:
                        date_str = date_match.group(1)
                        try:
                            date = datetime.strptime(date_str, "%d-%b-%Y %H:%M:%S")
                            response_times.append(date)
                        except ValueError:
                            continue

            if response_times:
                avg_time = sum((max(response_times) - time for time in response_times), 
                             timedelta()) / len(response_times)
                return f"{avg_time.days} days, {avg_time.seconds//3600} hours"
            return "N/A"
        except Exception:
            return "N/A"

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
        """Export report as PDF with proper formatting"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")]
        )
        
        if file_path:
            try:
                # Create PDF object with A4 size
                pdf = FPDF(format='A4')
                pdf.add_page()

                # Set default font
                pdf.set_font("Arial", "", 12)

                # Add title
                pdf.set_font("Arial", "B", 16)
                pdf.cell(0, 10, "Email Audit Report", ln=True, align="C")
                pdf.ln(10)

                # Add timestamp
                pdf.set_font("Arial", "I", 10)
                pdf.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
                pdf.ln(10)

                # Summary section
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "1. Summary", ln=True)
                pdf.ln(5)

                pdf.set_font("Arial", "", 10)
                for key, value in report_data['summary'].items():
                    pdf.cell(60, 8, key + ":", 0)
                    pdf.cell(0, 8, str(value), ln=True)
                pdf.ln(10)

                # Categories section
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "2. Email Categories", ln=True)
                pdf.ln(5)

                pdf.set_font("Arial", "", 10)
                for category, count in report_data['categories'].items():
                    pdf.cell(60, 8, category + ":", 0)
                    pdf.cell(0, 8, str(count), ln=True)
                pdf.ln(10)

                # Create and add charts
                # Response Status Chart
                plt.figure(figsize=(8, 4))
                sizes1 = [self.answered_count, self.unanswered_count]
                plt.pie(sizes1, labels=["Answered", "Unanswered"], 
                    autopct='%1.1f%%', colors=['#4CAF50', '#FF5722'])
                plt.title("Response Status Distribution")
                
                # Save the chart image as a temporary file
                chart_file_path = tempfile.mktemp(suffix='.png')
                plt.savefig(chart_file_path, format='png', dpi=300, bbox_inches='tight')
                plt.close()

                # Add the chart image to the PDF
                pdf.image(chart_file_path, x=10, y=pdf.get_y(), w=190)
                pdf.ln(130)  # Space for chart

                # Remove the temporary chart image after adding it to the PDF
                os.remove(chart_file_path)

                # Categories Chart
                plt.figure(figsize=(8, 4))
                sizes2 = list(self.email_categories.values())
                labels2 = list(self.email_categories.keys())
                plt.pie(sizes2, labels=labels2, autopct='%1.1f%%')
                plt.title("Email Categories Distribution")

                # Save the second chart image as a temporary file
                chart_file_path = tempfile.mktemp(suffix='.png')
                plt.savefig(chart_file_path, format='png', dpi=300, bbox_inches='tight')
                plt.close()

                # Add the second chart image to the PDF
                pdf.image(chart_file_path, x=10, y=pdf.get_y(), w=190)
                pdf.ln(130)  # Space for chart

                # Remove the temporary chart image after adding it to the PDF
                os.remove(chart_file_path)

                # Detailed Email List
                pdf.add_page()
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "3. Detailed Email List", ln=True)
                pdf.ln(5)

                pdf.set_font("Arial", "", 10)
                for email in report_data['emails']:
                    # Email number
                    pdf.set_font("Arial", "B", 10)
                    pdf.cell(0, 8, f"Email #{email['Sl. No']}", ln=True)

                    # Mail info with proper formatting
                    pdf.set_font("Arial", "", 10)
                    mail_info_lines = email['Mail-Info'].split('\n')
                    for line in mail_info_lines:
                        pdf.cell(0, 6, line, ln=True)

                    # Status
                    pdf.cell(0, 6, f"Status: {email['State']}", ln=True)

                    # Separator
                    pdf.cell(0, 2, "_" * 90, ln=True)
                    pdf.ln(5)

                    # Check if new page is needed
                    if pdf.get_y() > 250:
                        pdf.add_page()
                        pdf.set_font("Arial", "", 10)

                # Save PDF to the specified file path
                pdf.output(file_path)
                messagebox.showinfo("Success", "PDF report has been generated successfully!")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate PDF: {str(e)}")



    def export_csv(self, report_data):
        """Export report as CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if file_path:
            # Prepare data for CSV
            csv_data = []
            
            # Add summary
            csv_data.append(["SUMMARY"])
            for key, value in report_data['summary'].items():
                csv_data.append([key, value])
            
            csv_data.append([])  # Empty row for separation
            
            # Add categories
            csv_data.append(["EMAIL CATEGORIES"])
            for category, count in report_data['categories'].items():
                csv_data.append([category, count])
            
            csv_data.append([])  # Empty row for separation
            
            # Add email details
            csv_data.append(["DETAILED EMAIL LIST"])
            csv_data.append(["Sl. No", "Mail Info", "Status"])
            for email in report_data['emails']:
                csv_data.append([
                    email['Sl. No'],
                    email['Mail-Info'].replace('\n', ' | '),
                    email['State']
                ])
            
            # Write to CSV
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = pd.DataFrame(csv_data)
                writer.to_csv(f, index=False, header=False)
            
            messagebox.showinfo("Success", "CSV report has been generated successfully!")

    def export_excel(self, report_data):
        """Export report as Excel"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")]
        )
        
        if file_path:
            with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
                workbook = writer.book
                
                # Summary sheet
                summary_df = pd.DataFrame(list(report_data['summary'].items()),
                                        columns=['Metric', 'Value'])
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                
                # Categories sheet
                categories_df = pd.DataFrame(list(report_data['categories'].items()),
                                          columns=['Category', 'Count'])
                categories_df.to_excel(writer, sheet_name='Categories', index=False)
                
                # Email details sheet
                emails_df = pd.DataFrame(report_data['emails'])
                emails_df.to_excel(writer, sheet_name='Detailed Emails', index=False)
                
                # Add charts
                chart_sheet = workbook.add_worksheet('Charts')
                
                # Response status pie chart
                chart1 = workbook.add_chart({'type': 'pie'})
                chart1.add_series({
                    'name': 'Response Status',
                    'categories': ['Summary', 0, 0, 1, 0],
                    'values': ['Summary', 0, 1, 1, 1],
                })
                chart1.set_title({'name': 'Response Status Distribution'})
                chart_sheet.insert_chart('A2', chart1)
                
                # Categories pie chart
                chart2 = workbook.add_chart({'type': 'pie'})
                chart2.add_series({
                    'name': 'Email Categories',
                    'categories': ['Categories', 0, 0, len(report_data['categories'])-1, 0],
                    'values': ['Categories', 0, 1, len(report_data['categories'])-1, 1],
                })
                chart2.set_title({'name': 'Email Categories Distribution'})
                chart_sheet.insert_chart('A18', chart2)
                
            messagebox.showinfo("Success", "Excel report has been generated successfully!")

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

    def determine_email_state(self, msg, has_reply, email_threads):
        """Determine if an email is answered or unanswered"""
        support_email = self.email
        from_addr = msg["From"]
        subject = msg.get("Subject", "")

        # Check if it's from support team
        if support_email in from_addr:
            return "Answered"

        # Check if it has received a reply
        if has_reply:
            return "Answered"

        # Check if it's a reply to previous email
        if subject.lower().startswith("re:"):
            return "Answered"

        # Check references
        references = msg.get("References", "").split() + [msg.get("In-Reply-To", "")]
        if any(ref in email_threads for ref in references):
            return "Answered"

        return "Unanswered"

    def decode_subject(self, subject):
        """Decode email subject"""
        if subject is None:
            return "No Subject"
        try:
            decoded_list = decode_header(subject)
            decoded_subject = ""
            for content, encoding in decoded_list:
                if isinstance(content, bytes):
                    decoded_subject += content.decode(encoding if encoding else "utf-8")
                else:
                    decoded_subject += str(content)
            return decoded_subject
        except:
            return subject

    def convert_to_ist(self, date_str):
        """Convert email date to IST timezone"""
        try:
            email_date = email.utils.parsedate_to_datetime(date_str)
            ist_tz = pytz.timezone("Asia/Kolkata")
            return email_date.astimezone(ist_tz).strftime("%d-%b-%Y %H:%M:%S")
        except (TypeError, ValueError):
            return date_str

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailClientApp(root)
    root.mainloop()
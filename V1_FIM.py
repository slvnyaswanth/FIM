import streamlit as st

import hashlib
import os
import smtplib
import time
import sys
from email.mime.text import MIMEText
from tkinter import filedialog
import requests
import tkinter as tk

class TeeStdout:
        def __init__(self, original_stdout, log_file):
            self.original_stdout = original_stdout
            self.log_file = log_file
        def write(self, text):
            self.original_stdout.write(text)
            self.log_file.write(text)
        def flush(self):
            self.original_stdout.flush()
            self.log_file.flush()

def main():
    
    st.title('File Integrity Monitoring')
    sender_email = "senderemail"
    sender_password = "senderemail_password"
    receiver_email = 'receiver email address' #Enter the password that is created in APP Passwords in manage your google account
                                             #website be sure app passwords options appears after making enabling 2 step verification
    smtp_server = 'smtp.gmail.com'
    smtp_port = '587'
    output = []
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)
    directory = ''
    original_files = {}
    log_file = open('Enter your log file location to log data after exiting project', 'a')
    original_stdout = sys.stdout
    flag=False
    ck=False
    ano=False
    if st.button("Start Monitoring"):
        original_stdout = sys.stdout
        print("start")
        flag=True
        sys.stdout = TeeStdout(original_stdout, log_file)
        directory = st.text_input('Selected folder:', filedialog.askdirectory(master=root))  
        #store  hash codes of files before starting monitoring
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                hash1 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
                original_files[filepath] = hash1

        # Open the logfile in append mode
        log_file = open('Enter your log file location to log data after exiting project', 'a')  
    if st.button("save and exit"):
        ck=True
        flag=False
        ano=True
        sys.stdout = original_stdout
        original_stdout.flush()
        log_file.flush()
        log_file.close()
        os.kill(os.getpid(),2)   
    if ano:
            flag=False
    if flag:
        try:
            out = st.empty()
            
            while True:
                    current_files = {}
                    for root, dirs, files in os.walk(directory):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            hash1 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
                            current_files[filepath] = hash1
                    # Check for added files
                    added_files = list(set(current_files) - set(original_files))
                    if added_files:
                        print("Added files:")
                        for file in added_files:
                            print(file)
                            output.append("Files added scanning with virustotal:" + str(file))
                            output1 = "\n".join(str(c) for c in output)
                            # Update the text in the container
                            out.text(output1)
                            # Virus scanning
                            url = "https://www.virustotal.com/api/v3/files"
                            files = {"file": (file, open(file, "rb"), "text/plain/application/x-msdownload")}
                            headers = {
                                "accept": "application/json",
                                "x-apikey": "Enter your api key after creating account in virustotal "
                            }

                            response = requests.post(url, files=files, headers=headers)
                            temp = response.json()
                            ck_url = temp['data']['links']['self']
                           
                            res = requests.get(ck_url, headers=headers)
                            t1 = res.json()
                            if (t1['data']['attributes']['stats']['malicious'] > 0 and
                                    t1['data']['attributes']['stats'][
                                        'suspicious'] > 0):
                                output.append("virus detected in" )
                                output1 = "\n".join(str(c) for c in output)
                                # Send email notification
                                message = MIMEText(f"File modified: {file}")
                                message['From'] = sender_email
                                message['To'] = receiver_email
                                message['Subject'] = f"Infected file has been added"
                                with smtplib.SMTP(smtp_server, smtp_port) as server:
                                    server.starttls()
                                    print("Sending email as file is infected....")
                                    server.login(sender_email, sender_password)
                                    server.sendmail(sender_email, receiver_email, message.as_string())
                            else:
                                output.append(" No virus detected in Added file :" + str(file))
                                output1 = "\n".join(str(c) for c in output)
                                out.text(output1)

                    # Check for deleted files
                    deleted_files = list(set(original_files) - set(current_files))
                    if deleted_files:
                        # print("Deleted files:")
                        for file in deleted_files:
                            print("Deleted file:", file)
                            output.append("Deleted file:" + str(file))
                            output1 = "\n".join(str(c) for c in output)
                            # Update the text in the container
                            out.text(output1)
                            # Send email notification
                            message = MIMEText(f"File deleted: {file}")
                            message['From'] = sender_email
                            message['To'] = receiver_email
                            message['Subject'] = f"File deleted: {file}"
                            with smtplib.SMTP(smtp_server, smtp_port) as server:
                                server.starttls()
                                server.login(sender_email, sender_password)
                                server.sendmail(sender_email, receiver_email, message.as_string())
                    # Check for modified files
                    for file in original_files:
                        if file in current_files and original_files[file] != current_files[file]:
                            print("Modified file:", file)
                            output.append("Modified file:" + f'{file}')
                            # st.write(output_area)
                            output1 = "\n".join(str(c) for c in output)
                            # Update the text in the container
                            out.text(output1)
                    # Wait for 1 minute before checking again
                    time.sleep(1)
                    # Update the original list of files
                    original_files = current_files.copy()
                    
                    if ck:
                        raise(KeyboardInterrupt)            
        except(KeyboardInterrupt):
            # Restore sys.stdout to its original value
            sys.stdout = original_stdout
            # Close the logfile
            log_file.close()
if __name__ == '__main__':
    main()

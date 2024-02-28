import tkinter as tk
from tkinter import ttk
import pandas as pd
from mitreattack.stix20 import MitreAttackData

class HackingProbabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Therapy: Hacking Probability Scorer")
        self.root.geometry("800x550")

        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Helvetica', 10))
        style.configure("TButton", padding=(10, 10), font=('Helvetica', 12), background="#2196F3", foreground="black")
        style.configure("TText", background="#ffffff", font=('Helvetica', 10))

        # Create a canvas with vertical and horizontal scrollbars
        self.canvas = tk.Canvas(self.root, bd=0, highlightthickness=0, scrollregion=(0, 0, 2000, 2000))
        self.h_scrollbar = ttk.Scrollbar(self.root, orient="horizontal", command=self.canvas.xview)
        self.h_scrollbar.pack(side="bottom", fill="x")
        self.v_scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.v_scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.configure(xscrollcommand=self.h_scrollbar.set, yscrollcommand=self.v_scrollbar.set)

        # Create a frame inside the canvas to hold all widgets
        self.scroll_frame = ttk.Frame(self.canvas, style="TFrame")
        self.scroll_frame_window = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")

        # Set up the canvas to be scrollable
        self.scroll_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind("<MouseWheel>", self.on_mousewheel)

        self.probability_label = tk.Label(self.scroll_frame, text="", font=('Helvetica', 10))
        self.probability_label.grid(row=0, column=0, pady=5, sticky="e")

        self.excel_output_label = tk.Label(self.scroll_frame, text="", font=('Helvetica', 10))
        self.excel_output_label.grid(row=1, column=0, pady=5, sticky="e")

        self.mitigation_label = tk.Label(self.scroll_frame, text="", font=('Helvetica', 10))
        self.mitigation_label.grid(row=2, column=0, pady=5, sticky="e")

        self.output_text = tk.Text(self.scroll_frame, wrap=tk.WORD, height=20, width=70, font=('Helvetica', 10), bd=2, relief=tk.GROOVE)
        self.output_text.grid(row=0, column=1, rowspan=2, padx=20, pady=5, sticky="nsew")

        self.malware_text = tk.Text(self.scroll_frame, wrap=tk.WORD, height=20, width=70, font=('Helvetica', 10), bd=2, relief=tk.GROOVE)
        self.malware_text.grid(row=2, column=1, padx=20, pady=5, sticky="nsew")

        self.mitigation_text = tk.Text(self.scroll_frame, wrap=tk.WORD, height=20, width=70, font=('Helvetica', 10), bd=2, relief=tk.GROOVE)
        self.mitigation_text.grid(row=4, column=1, padx=20, pady=5, sticky="nsew")

        # Configure weight to allow the Text widget to expand
        self.scroll_frame.columnconfigure(1, weight=1)
        self.scroll_frame.rowconfigure(0, weight=1)

        # Widgets dictionary to store created widgets for dynamic updating
        self.widgets_dict = {}

        self.create_dropdown("Network Architecture", self.assign_hacking_probability_score,
                             "Choose the type of network architecture:\n\n"
                             "Zero Trust Architecture (ZTA): Modern security model focusing on strict identity verification.\n"
                             "Microsegmented Network: Network is divided into segments for improved security.\n"
                             "Network Access Control (NAC): Controls access to the network based on user/device attributes.\n"
                             "Distributed Networks: Network is spread across multiple locations.\n"
                             "Flat Perimeter Networks: Traditional network model with a single security perimeter.\n"
                             "Legacy Systems: Outdated and unsupported network infrastructure.\n"
                             "Bring Your Own Device Networks: Allows employees to use personal devices on the network.\n"
                             "None: No specific network architecture in place.", row=0)

        self.create_dropdown("Inventory", self.assign_inventory_probability_score,
                             "Select the type of inventory:\n\n"
                             "Air-gapped systems: Physically isolated from other networks.\n"
                             "IOT: Internet of Things devices.\n"
                             "Physical Servers: Dedicated servers in a physical location.\n"
                             "Obsolete systems: Outdated and no longer supported systems.", row=1)

        self.create_dropdown("Digital Assets", self.assign_digital_assets_probability_score,
                             "Choose the type of digital assets:\n\n"
                             "Non-Critical information: Low-risk data.\n"
                             "Customer Lists: Lists of customer information.\n"
                             "User Credentials: Logins and passwords.\n"
                             "Employee Records: Information about employees.\n"
                             "Intellectual Property: Company's intellectual assets.\n"
                             "Sensitive and Financial Data: High-risk financial information.\n"
                             "Healthcare Records: Patient health information.\n"
                             "Government data: Sensitive government-related data.\n"
                             "Industrial Control Systems(ICS): Systems controlling industrial processes.\n"
                             "Product designs: Designs and plans for products.\n"
                             "Critical Infrastructure: Crucial systems for an organization.", row=2)

        self.create_dropdown("Third Party Services", self.assign_third_party_and_cloud_probability_score,
                             "Choose the type of third-party services:\n\n"
                             "Private Cloud or managed cloud: Cloud services managed for internal use only.\n"
                             "Risk Management Programs: Programs to assess and manage risks associated with third-party services.\n"
                             "Software as a service: Cloud-based software provided as a service.\n"
                             "Auto Scaling to foreign servers: Automatically scaling resources to servers in foreign locations.\n"
                             "Third-Party Data Providers: External providers offering data services.\n"
                             "Third party Research and Development Data: Research and development services from external parties.\n"
                             "Data managed locally: Data stored and managed on local servers.\n"
                             "No cloud: No use of cloud services.", row=3)

        self.create_dropdown("Data Flow Methods", self.assign_Data_flow_probability_score,
                             "Choose the method of data flow:\n\n"
                             "Role-Based Access Controls(RBAC): Access controls based on user roles.\n"
                             "VPNs: Virtual Private Networks for secure data transmission.\n"
                             "Data Loss Prevention (DLP) System Implemented: System to prevent unauthorized data loss.\n"
                             "HeaNet filesender: Secure file transfer service provided by HeaNet.\n"
                             "SSH File Transfer Protocols: Secure Shell protocols for file transfer.\n"
                             "Managed Work/Staff emails, e.g., Outlook: Managed email system for staff.\n"
                             "Personal emails: Use of personal email for communication.\n"
                             "None: No defined data flow methods.", row=4)
        
        self.create_dropdown("Security Policies", self.assign_security_policies_and_procedures_probability_score,
                             "Choose the security policies and procedures:\n\n"
                             "Security Awareness and Training Policy: Policy for educating and training employees on security.\n"
                             "Vendor and Third-Party Security Policy: Policy addressing security considerations with vendors.\n"
                             "Data Classification and Handling Policy: Policy for classifying and handling sensitive data.\n"
                             "Access Control Policy, Password Policy: Policies for controlling access and managing passwords.\n"
                             "Acceptable Use Policy: Policy defining acceptable use of company resources.\n"
                             "Most policies applied but no awareness training: Implementation of most policies with no awareness training.\n"
                             "Remote Work and BYOD Policy if start-up if full-time online: Policies for remote work and Bring Your Own Device.\n"
                             "Only one policy applied, e.g., Bring Your Own Device (BYOD) Policy only: Implementation of a single policy.\n"
                             "None: No security policies in place.", row=5)

        self.create_dropdown("Software Patch Management", self.assign_patch_managment_probability_score,
                             "Choose the software patch management system:\n\n"
                             "Manual Patch Management: Manual process for applying software patches.\n"
                             "Outsourced Patch Management: Patch management outsourced to a third party.\n"
                             "Automated Patch Management: Automated system for applying software patches.\n"
                             "Cloud-Based Patch Management: Patch management system based in the cloud.\n"
                             "Patch as a Service (PaaS): Software patches provided as a service.\n"
                             "Security Information and Event Management (SIEM) Integration: Integration with SIEM for patch management.\n"
                             "Vulnerability Management: System for managing vulnerabilities.\n"
                             "DevOps-Integrated Patching: Integration of patching into the DevOps process.\n"
                             "Risk-Based Patch Management: Patch management based on risk assessment.\n"
                             "No Software Patch Management: No patch management system in place.", row=6)

        self.create_dropdown("Monitoring and Detection", self.assign_monitoring_and_detection_probability_score,
                             "Choose the monitoring and detection systems:\n\n"
                             "Security Information and Event Management (SIEM): SIEM system for log analysis.\n"
                             "Endpoint Detection and Response (EDR): System for detecting and responding to endpoint threats.\n"
                             "File Integrity Monitoring (FIM): Monitoring changes to files and file systems.\n"
                             "Security Orchestration, Automation, and Response (SOAR): Automated response to security incidents.\n"
                             "Intrusion Detection System (IDS): System for detecting unauthorized access.\n"
                             "Network Traffic Analysis (NTA): Analysis of network traffic patterns.\n"
                             "User and Entity Behavior Analytics (UEBA): Monitoring user behavior for anomalies.\n"
                             "Anomaly Detection: Detection of unusual patterns or behavior.\n"
                             "Log Management: Centralized management of logs.\n"
                             "None: No monitoring and detection systems in place.", row=7)

        self.create_dropdown("Incident Response Plans", self.assign_incident_response_probability_score,
                             "Choose the incident response plans:\n\n"
                             "Continuous Improvement of Systems: Ongoing improvement of security systems.\n"
                             "Proactive Incident Response Plan: Proactively designed incident response plan.\n"
                             "Integrating systems with Security Operations: Integration of systems with security operations.\n"
                             "Playbook-Based Incident Response: Incident response based on predefined playbooks.\n"
                             "Tabletop Exercises: Simulation exercises to test incident response.\n"
                             "Automation-Driven Incident Response: Incident response driven by automation.\n"
                             "Cloud-Centric Incident Response: Incident response designed for cloud-based environments.\n"
                             "Collaborative Incident Response: Collaborative approach to incident response.\n"
                             "Communication and Public Relations Integration: Integration with communication and public relations.\n"
                             "Regulatory Compliance Adherence: Adherence to regulatory compliance in incident response.\n"
                             "None: No incident response plans in place.", row=8)

        self.create_dropdown("Social Engineering Testing", self.assign_Social_Engineering_Testing_probability_score,
                             "Choose the social engineering testing methods:\n\n"
                             "Almost all techniques listed applied - Phishing Simulations, Vishing (Voice Phishing), Smishing (SMS Phishing), Impersonation Testing, Baiting (Physical Media Drops), USB Drop Tests, Tailgating Tests.\n"
                             "None: No social engineering testing conducted.", row=9)

        self.create_dropdown("Business Location", self.assign_Business_Location_probability_score,
                             "Choose the business location:\n\n"
                             "Latin America: Business operations in Latin America.\n"
                             "Africa: Business operations in Africa.\n"
                             "Middle East: Business operations in the Middle East.\n"
                             "North America: Business operations in North America.\n"
                             "Europe: Business operations in Europe.\n"
                             "Asia: Business operations in Asia.", row=10)

        self.Risk_button = ttk.Button(self.scroll_frame, text="Calculate Risk Probability", command=self.calculate_risk_probability, style="TButton")
        self.Risk_button.grid(row=3, column=1, pady=10, columnspan=2)

        self.mit_button = ttk.Button(self.scroll_frame, text="Request Mitigations", command=self.request_mitigations, style="TButton")
        self.mit_button.grid(row=5, column=1, pady=10, columnspan=2)

        style.configure("TButton", padding=(10, 10), font=('Helvetica', 12), background="#2196F3", foreground="black")

    def create_dropdown(self, label_text, function, description, row):
        frame = ttk.Frame(self.scroll_frame, style="TFrame", padding="5")
        frame.grid(row=row, column=0, sticky="w", pady=(0, 5))

        label = ttk.Label(frame, text=label_text, style="TLabel")
        label.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))

        description_label = ttk.Label(frame, text=description, wraplength=400, justify=tk.LEFT, style="TLabel")
        description_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))

        options = ["Select an option"] + self.get_options(label_text)
        var = tk.StringVar(value=options[0])
        dropdown = ttk.Combobox(frame, textvariable=var, values=options, state="readonly")
        dropdown.grid(row=0, column=1, sticky=tk.W, pady=(0, 2))

        # Store the dropdown widget and corresponding probability function in the dictionary
        self.widgets_dict[label_text] = {"widget": dropdown, "function": function}

      
    def calculate_risk_probability(self):
       all_results = []
       all_malware_descriptions = []

    # Iterate through each dropdown and calculate the risk probability
       for label_text, widget_info in self.widgets_dict.items():
          selected_option = widget_info["widget"].get()
          function = widget_info["function"]
        # Fetch the actual name of the selected option
          option_name = selected_option if selected_option != "Select an option" else "Not Selected"

          probability_score, paragraph, _, malware_description, _ = function(selected_option)
          all_results.append(
            f"{label_text}:\nSelected Option: {option_name}\nProbability Score: {probability_score}\nPossible Attack Campaigns:\n{paragraph}\n\n"
          )

          if malware_description is not None:
            all_malware_descriptions.append(
                f"{label_text}:\nSelected Option: {option_name}\nPossible malware tactic:\n{malware_description}\n"
            )

    # Display the results in the output_text widget
       self.output_text.delete(1.0, tk.END)  # Clear existing content
       output_text_content = "\n\n".join(filter(None, all_results))
       self.output_text.insert(tk.END, output_text_content)

    # Display malware descriptions in the malware_text widget
       self.malware_text.delete(1.0, tk.END)  # Clear existing content
       mal_text_content = "\n\n".join(filter(None, all_malware_descriptions))
       self.malware_text.insert(tk.END, mal_text_content)

    def request_mitigations(self):
       all_mitigation_descriptions = []

    # Iterate through each dropdown and request mitigations
       for label_text, widget_info in self.widgets_dict.items():
          selected_option = widget_info["widget"].get()
          function = widget_info["function"]
        # Fetch the actual name of the selected option
          option_name = selected_option if selected_option != "Select an option" else "Not Selected"

          _, _, mitigation_description, _, mit_data = function(selected_option)

        # Check if mitigation_description is not None before appending
          if mitigation_description is not None:
            mitigation_column = '\n'.join(mit_data)
            all_mitigation_descriptions.append(
                f"{label_text}:\nSelected Option: {option_name}\nSuggested Mitigation:\n{mitigation_description}\nTechniques mitigated:\n{mitigation_column}\n"
            )

    # Display all mitigation descriptions in the mitigation_text widget
       self.mitigation_text.delete(1.0, tk.END)  # Clear existing content
       mitigation_text_content = "\n\n".join(filter(None, all_mitigation_descriptions))
       self.mitigation_text.insert(tk.END, mitigation_text_content)
    # Display the results in the output_text widget
       


    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.itemconfig(self.scroll_frame_window, width=event.width)  # Updated this line

    def on_canvas_configure(self, event):
        canvas_width = event.width
        self.canvas.itemconfig(self.scroll_frame_window, width=canvas_width)  # Updated this line

    def on_mousewheel(self, event):
        self.canvas.xview_scroll(-1 * int(event.delta/120), "units")  # Adjust the scroll speed if needed

 # Updated this line


    def calculate_probability(self, function, selected_option):
        if selected_option == "Select an option":
            result = "Please select an option."
        else:
            probability_score, output_value = function(selected_option)
            self.update_output_labels(probability_score, output_value)

    def update_output_labels(self, probability_score, output_value):
        # Update the probability label
        self.probability_label.config(text=f"Probability Score: {probability_score}")

        # Update the output text
        self.output_text.delete(1.0, tk.END)  # Clear existing content
        self.output_text.insert(tk.END, f"Probability Score: {probability_score}\n\n")
        self.output_text.insert(tk.END, f"Excel Output:\n{output_value}\n\n")



    def get_options(self, label_text):
        if label_text == "Network Architecture":
            return ["Zero Trust Architecture (ZTA)", "Microsegmented Network",
                    "Network Access Control (NAC)", "Distributed Networks",
                    "Flat Perimeter Networks", "Legacy Systems", "Bring Your Own Device Networks", "None"]
        elif label_text == "Inventory":
            return ["Air-gapped systems", "IOT", "Physical Servers", "Obsolete systems"]
        elif label_text == "Digital Assets":
            return ["Non-Critical information", "Customer Lists", "User Credentials", "Employee Records",
                    "Intellectual Property", "Sensitive and Financial Data", "Healthcare Records",
                    "Government data", "Industrial Control Systems(ICS)", "Product designs", "Critical Infrastructure"]
        elif label_text == "Third Party Services":
            return ["Private Cloud or managed cloud", "Risk Management Programs",
                    "Software as a service", "Auto Scaling to foreign servers",
                    "Third-Party Data Providers", "Third party Research and Development Data",
                    "Data managed locally", "No cloud"]
        elif label_text == "Data Flow Methods":
            return ["Role-Based Access Controls(RBAC)", "VPNs",
                    "Data Loss Prevention (DLP) System Implemented",
                    "HeaNet filesender", "SSH File Transfer Protocols",
                    "Managed Work/Staff emails, eg Outlook",
                    "Personal emails", "None"]
        elif label_text == "Security Policies":
            return ["Security Awareness and Training Policy", "Vendor and Third-Party Security Policy",
                    "Data Classification and Handling Policy", "Access Control Policy, Password Policy",
                    "Acceptable Use Policy", "Most policies applied but no awareness training",
                    "Remote Work and BYOD Policy if start-up if fulltime online",
                    "Only one policy applied eg Bring Your Own Device (BYOD) Policy only", "None"]
        elif label_text == "Software Patch Management":
            return ["Manual Patch Management", "Outsourced Patch Management ",
                    "Automated Patch Management", "Cloud-Based Patch Management",
                    "Patch as a Service (PaaS)", "Security Information and Event Management (SIEM) Integration",
                    "Vulnerability Management", "DevOps-Integrated Patching", "Risk-Based Patch Management",
                    "No Software Patch Management"]
        elif label_text == "Monitoring and Detection":
            return ["Security Information and Event Management (SIEM)", "Endpoint Detection and Response (EDR)",
                    "File Integrity Monitoring (FIM)", "Security Orchestration, Automation, and Response (SOAR)",
                    "Intrusion Detection System (IDS)", "Network Traffic Analysis (NTA)",
                    "User and Entity Behavior Analytics (UEBA)", "Anomaly Detection", "Log Management",
                    "None"]
        elif label_text == "Incident Response Plans":
            return ["Continuous Improvement of Systems", "Proactive Incident Response Plan",
                    "Integrating systems with Security Operations", "Playbook-Based Incident Response",
                    "Tabletop Exercises", "Automation-Driven Incident Response", "Cloud-Centric Incident Response",
                    "Collaborative Incident Response", "Communication and Public Relations Integration",
                    "Regulatory Compliance Adherence", "None"]
        elif label_text == "Social Engineering Testing":
            return ["Almost all techniques listed applied - Phishing Simulations, Vishing (Voice Phishing), "
                    "Smishing (SMS Phishing), Impersonation Testing, Baiting (Physical Media Drops), "
                    "USB Drop Tests, Tailgating Tests", "None"]
        elif label_text == "Business Location":
            return ["Latin America", "Africa", "Middle East", "North America", "Europe", "Asia"]
        else:
            return []
   
    
    def assign_hacking_probability_score(self, network_architecture):
    # Initialize the default score
     probability_score_h = None
     mitigation_description = None
     malware_description = None
     paragraph = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if network_architecture == "Zero Trust Architecture (ZTA)" or network_architecture == "Microsegmented Network":
        probability_score_h = 1
     elif network_architecture == "Network Access Control (NAC)":
        probability_score_h = 2
     elif network_architecture == "Distributed Networks" or network_architecture == "Complex Network Topologies":
        probability_score_h = 3
     elif network_architecture == "Flat Perimeter Networks":
        probability_score_h = 4
     elif network_architecture == "Legacy Systems" or network_architecture == "Bring Your Own Device Networks" or network_architecture == "None":
        probability_score_h = 5
     if probability_score_h == 1 or probability_score_h == 2 or probability_score_h == 3 or probability_score_h == 4 or probability_score_h == 5:
            file_path = 'enterprise-attack-v13.1.xlsx'
            df = pd.read_excel(file_path)
            filtered_df = df[df['description'].str.contains('network access', case=False)]

            if not filtered_df.empty:
                output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                
                paragraph = '\n'.join(output_value)
            else:
                paragraph = "No match found in the 'description' column."

     if probability_score_h is not None:
        if probability_score_h > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software') 
            mitre_attack_data = MitreAttackData("enterprise-attack.json")


            # Define search terms for mitigations
            search_terms_m = ['Architect']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c"
            attacks_mitigated_by_m1030 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1030:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")

        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "
     return probability_score_h, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_inventory_probability_score(self, inventory):
        # Initialize the default score
     probability_score_i = None
     mitigation_description = None
     malware_description = None
     paragraph = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if inventory == "Air-gapped systems" or inventory == "IOT":
        probability_score_i = 3
     elif inventory == "Physical Servers":
        probability_score_i = 4
     elif inventory == "Obsolete systems":
        probability_score_i = 5
     if probability_score_i == 1 or probability_score_i == 2 or probability_score_i == 3 or probability_score_i == 4 or probability_score_i == 5:
            # Replace 'enterprise-attack-v13.1.xlsx' with the actual file path if it's not in the same directory as your script.
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['Servers']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
         paragraph = '\n'.join(output_value)

       else:
         paragraph = "No match found in the 'description' column."

     if probability_score_i is not None:
        if probability_score_i > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")


            # Define search terms for mitigations
            search_terms_m = ['servers']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--2c2ad92a-d710-41ab-a996-1db143bb4808"
            attacks_mitigated_by_m1053 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)
                for t in attacks_mitigated_by_m1053:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

     return probability_score_i, paragraph, mitigation_description, malware_description, mit_data

    def assign_digital_assets_probability_score(self, digital_asset):
    # Initialize the default score
     probability_score_d = None
     mitigation_description = None
     malware_description = None
     paragraph = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if digital_asset == "Non-Critical information":
        probability_score_d = 1
     elif digital_asset == "Customer Lists":
        probability_score_d = 2
     elif digital_asset == "User Credentials" or digital_asset == "Employee Records":
        probability_score_d = 3
     elif digital_asset == "Intellectual Property" or digital_asset == "Employee Records" or digital_asset == "Cryptocurrencies" or digital_asset == "Supplychains" or digital_asset == "Customer Communication Systems":
        probability_score_d = 4
     elif digital_asset == "Sensitive and Financial Data" or digital_asset == "Healthcare Records" or digital_asset == "Government data" or digital_asset == "Industrial Control Systems(ICS)" or digital_asset == "Product designs" or digital_asset == "Critical Infrastructure":
        probability_score_d = 5

     if probability_score_d == 1 or probability_score_d == 2 or probability_score_d == 3 or probability_score_d == 4 or probability_score_d == 5:
        # Replace 'enterprise-attack-v13.1.xlsx' with the actual file path if it's not in the same directory as your script.
        file_path = 'enterprise-attack-v13.1.xlsx'

        # Load the Excel file into a Pandas DataFrame
        df = pd.read_excel(file_path)

        search_terms = ['sensitive data']

        # Combine search terms using '|', which represents logical OR
        search_pattern = '|'.join(search_terms)

        # Filter rows where the "description" column contains any of the search terms
        filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

        # Check if there are any matching rows
        if not filtered_df.empty:
            # Output the values from the "description" column of all matching rows as a proper paragraph
            output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()

            # Create a proper paragraph by joining the output values
            paragraph = '\n'.join(output_value)

        else:
            paragraph = "No match found in the 'description' column."

        if probability_score_d is not None:
            if probability_score_d > 2:
                # Load the Excel file into a Pandas DataFrame for mitigations
                df_m = pd.read_excel(file_path, 'mitigations')
                df_m_s = pd.read_excel(file_path, 'software')
                mitre_attack_data = MitreAttackData("enterprise-attack.json")

                # Define search terms for mitigations
                search_terms_m = ['sensitive data']

                # Combine search terms using '|', which represents logical OR
                search_pattern_m = '|'.join(search_terms_m)

                # Filter rows where the "description" column contains any of the search terms
                filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
                filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

                # get techniques mitigated by
                mitigation_stix_id = "course-of-action--65401701-019d-44ff-b223-08d520bb0e7b"
                attacks_mitigated_by_m1057 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

                # Check if there are any matching rows for mitigations
                if not filtered_df_m.empty:
                    # Output the values from the "description" column of all matching rows as a proper paragraph
                    output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    # Create a proper paragraph by joining the output values for mitigations
                    mitigation_description = '\n'.join(output_values_m)
                    malware_description = '\n'.join(s_values)
                    for t in attacks_mitigated_by_m1057:
                        technique = t["object"]
                        mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
            else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
     return probability_score_d, paragraph, mitigation_description, malware_description, mit_data

    
    def assign_third_party_and_cloud_probability_score(self, third_part_and_cloud_services):
        # Initialize the default score
     probability_score_thp = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if third_part_and_cloud_services == "Private Cloud or managed cloud" or third_part_and_cloud_services == "Risk Management Programs":
        probability_score_thp = 1
     elif third_part_and_cloud_services == "Software as a service" or third_part_and_cloud_services == "Auto Scaling to foreign servers":
        probability_score_thp = 2
     elif third_part_and_cloud_services == "Third-Party Data Providers" or third_part_and_cloud_services == "Third party Research and Development Data":
        probability_score_thp = 3
     elif third_part_and_cloud_services == "Data managed locally" or third_part_and_cloud_services == "No cloud":
        probability_score_thp = 5
     if probability_score_thp == 1 or probability_score_thp == 2 or probability_score_thp == 3 or probability_score_thp == 4 or probability_score_thp == 5:
            
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['third party services']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
         paragraph = '\n'.join(output_value)
    
     else:
      paragraph = "No match found in the 'description' column."

     if probability_score_thp is not None:
        if probability_score_thp > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")


            # Define search terms for mitigations
            search_terms_m = ['services']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_ids = (
               "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c",
               "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f"
            )
            

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for mitigation_stix_id in mitigation_stix_ids:
                       attacks_mitigated = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)
                       
                       for t in attacks_mitigated:
                           technique = t["object"]
                           technique_id = mitre_attack_data.get_attack_id(technique.id)
                           mit_data.append(f"* {technique.name} ({technique_id})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

     return probability_score_thp, paragraph, mitigation_description, malware_description, mit_data
    
   
    def assign_Data_flow_probability_score(self, Data_flow):
        # Initialize the default score
     probability_score_df = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

     if Data_flow == "Role-Based Access Controls(RBAC)" or Data_flow == "VPNs":
        probability_score_df = 1
     elif Data_flow == "Data Loss Prevention (DLP) System Implemented":
        probability_score_df = 2
     elif Data_flow == "HeaNet filesender" or Data_flow == "SSH File Transfer Protocols":
        probability_score_df = 3
     elif Data_flow == "Managed Work/Staff emails, eg Outlook":
        probability_score_df = 4
     elif Data_flow == "Personal emails" or Data_flow == "None":
        probability_score_df = 5
     if probability_score_df == 1 or probability_score_df == 2 or probability_score_df == 3 or probability_score_df == 4 or probability_score_df == 5:
        file_path = 'enterprise-attack-v13.1.xlsx'

        # Load the Excel file into a Pandas DataFrame
        df = pd.read_excel(file_path)

        search_terms = ['file transfer', 'data transfer']

        # Combine search terms using '|', which represents logical OR
        search_pattern = '|'.join(search_terms)

        # Filter rows where the "description" column contains any of the search terms
        filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

        # Check if there are any matching rows
        if not filtered_df.empty:
            # Output the values from the "description" column of all matching rows as a proper paragraph
            output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()

            # Create a proper paragraph by joining the output values
            paragraph = '\n'.join(output_value)
            
        else:
            print("No match found in the 'description' column.")

        if probability_score_df is not None:
            if probability_score_df > 2:
                # Load the Excel file into a Pandas DataFrame for mitigations
                df_m = pd.read_excel(file_path, 'mitigations')
                df_m_s = pd.read_excel(file_path, 'software')
                mitre_attack_data = MitreAttackData("enterprise-attack.json")

                # Define search terms for mitigations
                search_terms_m = ['file']

                # Combine search terms using '|', which represents logical OR
                search_pattern_m = '|'.join(search_terms_m)

                # Filter rows where the "description" column contains any of the search terms
                filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
                filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

                # Check if there are any matching rows for mitigations
                if not filtered_df_m.empty:
                    # Output the values from the "description" column of all matching rows as a proper paragraph
                    output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    # Create a proper paragraph by joining the output values for mitigations
                    mitigation_description = '\n'.join(output_values_m)
                    malware_description = '\n'.join(s_values)

                    # get techniques mitigated by
                    mitigation_stix_ids = (
                        "course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46",
                        "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f",
                        "course-of-action--20a2baeb-98c2-4901-bad7-dc62d0a03dea",
                        "course-of-action--987988f0-cf86-4680-a875-2f6456ab2448"
                     )

                # Initialize a list to store techniques mitigated by each mitigation
                    for mitigation_stix_id in mitigation_stix_ids:
                       attacks_mitigated = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)
                       
                       for t in attacks_mitigated:
                           technique = t["object"]
                           technique_id = mitre_attack_data.get_attack_id(technique.id)
                           mit_data.append(f"* {technique.name} ({technique_id})")

                else:
                    mitigation_description = "No mitigation descriptions available."
                    malware_description = "No malware noted"
                    mit_data = ""

     return probability_score_df, paragraph, mitigation_description, malware_description, mit_data

    def assign_security_policies_and_procedures_probability_score(self, security_policies_and_procedures):
     
     probability_score_spp = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []
    
     if security_policies_and_procedures == "Security Awareness and Training Policy" or security_policies_and_procedures == "Vendor and Third-Party Security Policy" or security_policies_and_procedures == "Data Classification and Handling Policy" or security_policies_and_procedures =="Access Control Policy, Password Policy" or security_policies_and_procedures == "Acceptable Use Policy":
        probability_score_spp = 1
     elif security_policies_and_procedures == "Most policies applied but no awarness training":
        probability_score_spp = 2
     elif security_policies_and_procedures == "Remote Work and BYOD Policy if start-up if fulltime online":
        probability_score_spp = 3
     elif security_policies_and_procedures == "Only one policy applied eg Bring Your Own Device (BYOD) Policy only":
        probability_score_spp = 4
     elif security_policies_and_procedures == "None":
        probability_score_spp = 5
     if probability_score_spp == 1 or probability_score_spp == 2 or probability_score_spp == 3 or probability_score_spp == 4 or probability_score_spp == 5:
            
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['security policies']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
         paragraph = '\n'.join(output_value)
    
       else:
        paragraph = "No match found in the 'description' column."

     if probability_score_spp is not None:
        if probability_score_spp > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software') 
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['user']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                    # Output the values from the "description" column of all matching rows as a proper paragraph
                    output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                    # Create a proper paragraph by joining the output values for mitigations
                    mitigation_description = '\n'.join(output_values_m)
                    malware_description = '\n'.join(s_values)

                    # get techniques mitigated by
                    mitigation_stix_ids = (
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--609191bf-7d06-40e4-b1f8-9e11eb3ff8a6",
                        "course-of-action--2995bc22-2851-4345-ad19-4e7e295be264",
                        "course-of-action--23843cff-f7b9-4659-a7b7-713ef347f547",
                        "course-of-action--b045d015-6bed-4490-bd38-56b41ece59a0",
                        "course-of-action--987988f0-cf86-4680-a875-2f6456ab2448",
                        "course-of-action--2c2ad92a-d710-41ab-a996-1db143bb4808",
                        "course-of-action--93e7968a-9074-4eac-8ae9-9f5200ec3317",
                        "course-of-action--2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a"
                     )

                # Initialize a list to store techniques mitigated by each mitigation
                    for mitigation_stix_id in mitigation_stix_ids:
                       attacks_mitigated = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)
                       
                       for t in attacks_mitigated:
                           technique = t["object"]
                           technique_id = mitre_attack_data.get_attack_id(technique.id)
                           mit_data.append(f"* {technique.name} ({technique_id})")

            else:
                  mitigation_description = "No mitigation descriptions available."
                  malware_description = "No malware noted"
                  mit_data =""
     return probability_score_spp, paragraph, mitigation_description, malware_description, mit_data


    def assign_patch_managment_probability_score(self, patch_managment):
        # Initialize the default score
     probability_score_pm = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

    
     if patch_managment == "Manual Patch Management":
        probability_score_pm = 4
     elif patch_managment == "Outsourced Patch Management":
        probability_score_pm = 3
     elif patch_managment == "Automated Patch Management" or patch_managment == "Cloud-Based Patch Management" or patch_managment == "Patch as a Service (PaaS)" or patch_managment == "Security Information and Event Management (SIEM) Integration":
        probability_score_pm = 2
     elif patch_managment == "Vulnerability Management" or patch_managment == "DevOps-Integrated Patching" or patch_managment == "Risk-Based Patch Management":
        probability_score_pm = 1
     elif patch_managment == "No Software Patch Management":
        probability_score_pm = 5
     if probability_score_pm == 1 or probability_score_pm == 2 or probability_score_pm == 3 or probability_score_pm == 4 or probability_score_pm == 5:
            
         file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
         df = pd.read_excel(file_path)  

         search_terms = ['patch']

      # Combine search terms using '|', which represents logical OR
         search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
         filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
         if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
            output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
            paragraph = '\n'.join(output_value)
    
         else:
            paragraph = "No match found in the 'description' column."

     if probability_score_pm is not None:
        if probability_score_pm > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['update']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"
            attacks_mitigated_by_m1051 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1051:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

     return probability_score_pm, paragraph, mitigation_description,malware_description, mit_data


    def assign_monitoring_and_detection_probability_score(self, monitoring_and_detection):
         # Initialize the default score
     probability_score_md = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if monitoring_and_detection == "Security Information and Event Management (SIEM)" or monitoring_and_detection == "Endpoint Detection and Response (EDR)" or monitoring_and_detection == "File Integrity Monitoring (FIM)" or monitoring_and_detection =="Security Orchestration, Automation, and Response (SOAR)":
        probability_score_md = 2
     elif monitoring_and_detection == "Intrusion Detection System (IDS)" or monitoring_and_detection == "Network Traffic Analysis (NTA)" or monitoring_and_detection == "User and Entity Behavior Analytics (UEBA)" or monitoring_and_detection == "Anomaly Detection" or monitoring_and_detection == "Log Management":
        probability_score_md = 3
     elif monitoring_and_detection == "None":
        probability_score_md = 5
     if probability_score_md == 1 or probability_score_md == 2 or probability_score_md == 3 or probability_score_md == 4 or probability_score_md == 5:
            
      file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
      df = pd.read_excel(file_path)  

      search_terms = ['detection']

      # Combine search terms using '|', which represents logical OR
      search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
      if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
        paragraph = '\n'.join(output_value)

     else:
         paragraph = "No match found in the 'description' column."

     if probability_score_md is not None:
        if probability_score_md > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['detection']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_ids = (
                "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c",
                "course-of-action--20a2baeb-98c2-4901-bad7-dc62d0a03dea"
            )

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for mitigation_stix_id in mitigation_stix_ids:
                       attacks_mitigated = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)
                       
                       for t in attacks_mitigated:
                           technique = t["object"]
                           technique_id = mitre_attack_data.get_attack_id(technique.id)
                           mit_data.append(f"* {technique.name} ({technique_id})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

     return probability_score_md, paragraph, mitigation_description, malware_description, mit_data


    def assign_incident_response_probability_score(self, incident_response):
         # Initialize the default score
     probability_score_ir = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if incident_response == "Continuous Improvement of Systems" or incident_response == "Proactive Incident Response Plan" or incident_response == "Integrating systems with Security Operations":
        probability_score_ir = 1
     elif incident_response == "Playbook-Based Incident Response" or incident_response == "Tabletop Exercises" or incident_response == "Automation-Driven Incident Response" or incident_response == "Cloud-Centric Incident Response":
        probability_score_ir = 2
     elif incident_response == "Collaborative Incident Response" or incident_response == "Communication and Public Relations Integration" or incident_response == "Regulatory Compliance Adherence":
        probability_score_ir = 3
     elif incident_response == "None":
        probability_score_ir = 5
     if probability_score_ir == 1 or probability_score_ir == 2 or probability_score_ir == 3 or probability_score_ir == 4 or probability_score_ir == 5:
             
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['incident response']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
         paragraph = '\n'.join(output_value)

       else:
         paragraph = "No match found in the 'description' column."

     if probability_score_ir is not None:
        if probability_score_ir > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['store']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b"
            attacks_mitigated_by_m1053 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1053:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

     return probability_score_ir, paragraph, mitigation_description, malware_description, mit_data

    def assign_Social_Engineering_Testing_probability_score(self, Social_Engineering_Testing):
        # Initialize the default score
      probability_score_see = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

    # Use if statements to assign scores based on the network architecture
      if Social_Engineering_Testing == "Almost all techniques listed applied - Phishing Simulations, Vishing (Voice Phishing), Smishing (SMS Phishing), Impersonation Testing, Baiting (Physical Media Drops), USB Drop Tests, Tailgating Tests":
        probability_score_see = 2
      elif Social_Engineering_Testing == "None":
        probability_score_see = 5
      if probability_score_see == 1 or probability_score_see == 2 or probability_score_see == 3 or probability_score_see == 4 or probability_score_see == 5:
            
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['social engineering']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
         paragraph = '\n'.join(output_value)
       else:
         paragraph = "No match"
    

      if probability_score_see is not None:
        if probability_score_see > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['social']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a"
            attacks_mitigated_by_m1017 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1017:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

      return probability_score_see, paragraph, mitigation_description, malware_description, mit_data

    def assign_Business_Location_probability_score(self, Business_Location):
        # Initialize the default score
     probability_score_bl = None
     mitigation_description = None
     paragraph = None
     malware_description = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if Business_Location == "Latin America" or Business_Location == "Africa" or Business_Location =="Middle East":
        probability_score_bl = 2
     elif Business_Location == "North America":
        probability_score_bl = 3
     elif Business_Location == "Europe":
        probability_score_bl = 4
     elif Business_Location == "Asia":
        probability_score_bl = 5
     if probability_score_bl == 1 or probability_score_bl == 2 or probability_score_bl == 3 or probability_score_bl == 4 or probability_score_bl == 5:
    
       file_path = 'enterprise-attack-v13.1.xlsx'

      # Load the Excel file into a Pandas DataFrame
       df = pd.read_excel(file_path)  

       search_terms = ['region']

      # Combine search terms using '|', which represents logical OR
       search_pattern = '|'.join(search_terms)

      # Filter rows where the "description" column contains any of the search terms
       filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

     # Check if there are any matching rows
       if not filtered_df.empty:
      # Output the values from the "description" column of all matching rows as a proper paragraph
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
    
      # Create a proper paragraph by joining the output values
        paragraph = '\n'.join(output_value)
       else:
        paragraph = "No match found in the 'description' column."

     if probability_score_bl is not None:
        if probability_score_bl > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software') 
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
            search_terms_m = ['detection']

            # Combine search terms using '|', which represents logical OR
            search_pattern_m = '|'.join(search_terms_m)

            # Filter rows where the "description" column contains any of the search terms
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            #get techniques mitigated by
            mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
            attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
            if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                # Create a proper paragraph by joining the output values for mitigations
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description ="No malware noted"
            mit_data = " "
   

     return probability_score_bl, paragraph, mitigation_description, malware_description, mit_data
    

if __name__ == "__main__":
    root = tk.Tk()
    app = HackingProbabilityApp(root)
    root.mainloop()



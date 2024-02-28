from flask import Flask, render_template, request
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import base64
import pandas as pd
from mitreattack.stix20 import MitreAttackData
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
import io
import os
import matplotlib.pyplot as plt
import numpy as np


app = Flask(__name__)
# Configure the database URI
app.secret_key = 'your secret key'
 
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'cyber_users_info'

mysql = MySQL(app)

user_domain_measure_scores = {
        "Security Awareness Training": 4,
        "User Account Policies": 3,
        "Multi-factor Authentication (MFA)": 2,
        "Password Policies": 2,
        "User Activity Monitoring": 1,
        "Privilege Management": 1,
        "Endpoint Security Solutions": 1,
        "None": 5
      }

workstation_domain_measure_scores = {
    "Operating System Hardening": 4,
    "Application Whitelisting": 3,
    "Patch Management": 2,
    "Disk Encryption": 2,
    "Host-based Firewalls": 1,
    "Anti-malware Solutions": 1,
    "Remote Wipe Capability": 1,
    "None": 5
}

lan_domain_measure_scores = {
    "Intrusion Detection/Prevention Systems (IDS/IPS)": 4,
    "Network Segmentation": 3,
    "Network Access Control (NAC)": 2,
    "Switch Security Configuration": 2,
    "Network Monitoring": 1,
    "DNS Security": 1,
    "None": 5
}

lan_to_wan_domain_measure_scores = {
    "Firewalls": 4,
    "Intrusion Detection/Prevention Systems (IDS/IPS)": 3,
    "Virtual Private Networks (VPN)": 2,
    "Web Content Filtering": 2,
    "Proxy Servers": 1,
    "Gateway Antivirus": 1,
    "None": 5
}

wan_domain_measure_scores = {
    "Secure WAN Protocols (e.g., MPLS, IPsec)": 4,
    "Encrypted Communication Channels": 3,
    "DDoS Mitigation": 2,
    "Redundant Connections": 2,
    "Bandwidth Management": 1,
    "Quality of Service (QoS)": 1,
    "None": 5
}

remote_access_domain_measure_scores = {
    "Secure Remote Access Protocols (e.g., SSL VPN, SSH)": 4,
    "Endpoint Security Policies": 3,
    "Remote Desktop Protocol (RDP) Security": 2,
    "Session Timeout Policies": 2,
    "Remote Access Auditing": 1,
    "Two-Factor Authentication (2FA) for Remote Access": 1,
    "None": 5
}

system_application_domain_measure_scores = {
    "Secure Development Lifecycle (SDL) Practices": 4,
    "Application Whitelisting": 3,
    "Code Signing": 2,
    "Input Validation": 2,
    "Error Handling": 1,
    "Session Management": 1,
    "API Security": 1,
    "Data Encryption": 1,
    "Secure Configuration Management": 1,
    "None": 5
}


@app.route('/index', methods=['POST'])
def index():
    return render_template('index.html', user_domain_measure_scores = user_domain_measure_scores)

@app.route('/')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM account_info WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO account_info VALUES (NULL, % s, % s, % s)', (username, password, email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('signup.html', msg = msg)

@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM account_info WHERE username = % s AND password = % s', (username, password, ))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['name'] = account['username']
            msg = 'Logged in successfully !'
            return render_template('index.html', user_domain_measure_scores = user_domain_measure_scores, workstation_domain_measure_scores=workstation_domain_measure_scores, lan_domain_measure_scores=lan_domain_measure_scores, lan_to_wan_domain_measure_scores=lan_to_wan_domain_measure_scores, wan_domain_measure_scores=wan_domain_measure_scores, remote_access_domain_measure_scores=remote_access_domain_measure_scores, system_application_domain_measure_scores=system_application_domain_measure_scores, msg = msg)
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)
        

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


class YourRiskAssessmentClass:
   
    def assign_user_domain_probability_score(self, user_domain_security_measures):

      probability_score_ud = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

    # Calculate the average score for selected measures
      selected_d = [user_domain_measure_scores.get(item) for item in user_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0
      else:
         probability_score_ud = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'

        # Search for relevant terms in the description column of the Excel sheet
      df = pd.read_excel(file_path)
      search_terms = ['user','domain', 'security']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

        # Generate paragraph based on the matched descriptions
      if not filtered_df.empty:
         output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
         paragraph = '\n'.join(output_value)
      else:
         paragraph = "No match found in the 'description' column."

      if probability_score_ud is not None:
        if probability_score_ud > 2:
            # Load mitigations data and perform necessary operations
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['user','domain', 'security']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--609191bf-7d06-40e4-b1f8-9e11eb3ff8a6",
                        "course-of-action--2995bc22-2851-4345-ad19-4e7e295be264",
                        "course-of-action--23843cff-f7b9-4659-a7b7-713ef347f547",
                        "course-of-action--b045d015-6bed-4490-bd38-56b41ece59a0",
                        "course-of-action--20a2baeb-98c2-4901-bad7-dc62d0a03dea",
                        "course-of-action--b5dbb4c5-b0b1-40b1-80b6-e9e84ab90067",
                        "course-of-action--987988f0-cf86-4680-a875-2f6456ab2448",
                        "course-of-action--93e7968a-9074-4eac-8ae9-9f5200ec3317",
                        "course-of-action--2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a",
                        "course-of-action--2c2ad92a-d710-41ab-a996-1db143bb4808"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_ud, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_workstation_domain_probability_score(self, workstation_domain_security_measures):

      probability_score_wd = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [workstation_domain_measure_scores.get(item) for item in workstation_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_wd = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['workstation']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_wd is not None:
        if probability_score_wd > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['users', 'training']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--609191bf-7d06-40e4-b1f8-9e11eb3ff8a6",
                        "course-of-action--2995bc22-2851-4345-ad19-4e7e295be264",
                        "course-of-action--23843cff-f7b9-4659-a7b7-713ef347f547",
                        "course-of-action--987988f0-cf86-4680-a875-2f6456ab2448",
                        "course-of-action--2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_wd, paragraph, mitigation_description, malware_description, mit_data

    def assign_lan_domain_probability_score(self, lan_domain_security_measures):
      probability_score_ld = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [lan_domain_measure_scores.get(item) for item in lan_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_ld = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['local network']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_ld is not None:
        if probability_score_ld > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['network']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--20f6a9df-37c4-4e20-9e47-025983b1b39d",
                        "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f",
                        "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c",
                        "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_ld, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_lan_to_wan_domain_probability_score(self, lan_to_wan_domain_security_measures):
      probability_score_ltw = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [lan_to_wan_domain_measure_scores.get(item) for item in lan_to_wan_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_ltw = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['firewall', 'security']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_ltw is not None:
        if probability_score_ltw > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['network']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--20f6a9df-37c4-4e20-9e47-025983b1b39d",
                        "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f",
                        "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c",
                        "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_ltw, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_remote_access_domain_probability_score(self, remote_access_domain_security_measures):
      probability_score_rad = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [remote_access_domain_measure_scores.get(item) for item in remote_access_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_rad = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['remote access']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_rad is not None:
        if probability_score_rad > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['remote access', 'domain']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_id = "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f"
            attacks_mitigated_by_m1051 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1051:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
        else:
            mitigation_description = "No mitigation descriptions available."
            malware_description = "No malware noted"
            mit_data = " "

      return probability_score_rad, paragraph, mitigation_description, malware_description, mit_data

    def assign_wan_domain_probability_score(self, wan_domain_security_measures):
      probability_score_wan = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [wan_domain_measure_scores.get(item) for item in wan_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_wan = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['external network', 'internet']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_wan is not None:
        if probability_score_wan > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['network']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--20f6a9df-37c4-4e20-9e47-025983b1b39d",
                        "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f",
                        "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c",
                        "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_wan, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_system_application_domain_probability_score(self, system_application_domain_security_measures):
      probability_score_sad = None
      mitigation_description = None
      paragraph = None
      malware_description = None
      mit_data = []

      selected_d = [system_application_domain_measure_scores.get(item) for item in system_application_domain_security_measures]
      selected_scores = sum(selected_d)
      total = len(selected_d)
      if selected_scores == 0:
        return 0, None, None, None, None
      else:
        probability_score_sad = selected_scores // total

      file_path = 'enterprise-attack-v13.1.xlsx'
      df = pd.read_excel(file_path)
      search_terms = ['system', 'application', 'encryption']
      search_pattern = '|'.join(search_terms)
      filtered_df = df[df['description'].str.contains(search_pattern, case=False)]

      if not filtered_df.empty:
        output_value = filtered_df.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
        paragraph = '\n'.join(output_value)
      else:
        paragraph = "No match found in the 'description' column."

      if probability_score_sad is not None:
        if probability_score_sad > 2:
            df_m = pd.read_excel(file_path, 'mitigations')
            df_m_s = pd.read_excel(file_path, 'software')
            mitre_attack_data = MitreAttackData("enterprise-attack.json")

            search_terms_m = ['system', 'application', 'encryption']
            search_pattern_m = '|'.join(search_terms_m)
            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
            filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern, case=False)]

            mitigation_stix_ids = (
                        "course-of-action--b9f0c069-abbe-4a07-a245-2481219a1463",
                        "course-of-action--cc2399fd-3cd3-4319-8d0a-fbd6420cdaf8",
                        "course-of-action--7da0387c-ba92-4553-b291-b636ee42b2eb",
                        "course-of-action--590777b3-b475-4c7c-aaf8-f4a73b140312",
                        "course-of-action--e8242a33-481c-4891-af63-4cf3e4cf6aff",
                        "course-of-action--feff9142-e8c2-46f4-842b-bd6fb3d41157",
                        "course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46",
                        "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b",
                        "course-of-action--47e0e9fe-96ce-4f65-8bb1-8be1feacb5db",
                        "course-of-action--1dcaeb21-9348-42ea-950a-f842aaf1ae1f",
                        "course-of-action--2995bc22-2851-4345-ad19-4e7e295be264",
                        "course-of-action--b045d015-6bed-4490-bd38-56b41ece59a0",
                        "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c",
                        "course-of-action--2f316f6c-ae42-44fe-adf8-150989e0f6d3",
                        "course-of-action--9bb9e696-bff8-4ae1-9454-961fc7d91d5f",
                        "course-of-action--72dade3e-1cba-4182-b3b3-a77ca52f02a1",
                        "course-of-action--b5dbb4c5-b0b1-40b1-80b6-e9e84ab90067"
                      )

            if not filtered_df_m.empty:
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
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

      return probability_score_sad, paragraph, mitigation_description, malware_description, mit_data

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
    
def insert_user_scores(account_id, network_score, inventory_score, digital_assets_score, thirdparty_score, 
                       dataflow_score, security_policies_score, patch_score, monitoring_and_detection_score, 
                       incident_response_score, social_engineering_testing, business_location):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO user_scores (account_id, network_score, inventory_score, digital_assets_score, '
                   'thirdparty_score, dataflow_score, security_policies_score, patch_score, '
                   'monitoring_and_detection_score, incident_response_score, social_engineering_testing, '
                   'business_location) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                   (account_id, network_score, inventory_score, digital_assets_score, thirdparty_score, 
                    dataflow_score, security_policies_score, patch_score, monitoring_and_detection_score, 
                    incident_response_score, social_engineering_testing, business_location))
    mysql.connection.commit()

risk_assessment_instance = YourRiskAssessmentClass()

#@app.route('/')
#def index():
    #return render_template('index.html')  # Create an HTML file named index.html in the "templates" folder

@app.route('/calculate_risk', methods=['POST'])
def calculate_risk():
    
    selected_ud = request.form.getlist('user_domain')
    selected_wd = request.form.getlist('workstation_domain')
    selected_ld = request.form.getlist('lan_domain')
    selected_ltwd = request.form.getlist('lan_to_wan_domain')
    selected_wand = request.form.getlist('wan_domain')
    selected_rad = request.form.getlist('remote_access_domain')
    selected_sad = request.form.getlist('system_application_domain')
    selected_network_architecture = request.form.get('network_architecture')
    selected_inventory = request.form.get('inventory')
    selected_d = request.form.get('digital_assets')
    selected_t = request.form.get('third_party')
    selected_df = request.form.get('data_flow')
    selected_sp = request.form.get('Security_Policies')
    selected_pm = request.form.get('Patch_Managment')
    selected_md = request.form.get('Monitoring')
    selected_ir = request.form.get('incident_response')
    selected_s = request.form.get('Social_Engineering_Testing')
    selected_bl = request.form.get('Business_Location')
    # Use the risk assessment functions to calculate probability scores and get information
    ud_probability_score, ud_paragraph, ud_mitigation_description, ud_malware, ud_mit_data = risk_assessment_instance.assign_user_domain_probability_score(selected_ud)
    wd_score, wd_paragraph, wd_mitigation_description, wd_malware_desc, wd_mit_data = risk_assessment_instance.assign_workstation_domain_probability_score(selected_wd)
    ld_probability_score, ld_paragraph, ld_mitigation_desc, ld_malware, ld_mit_data = risk_assessment_instance.assign_lan_domain_probability_score(selected_ld)
    ltwd_score, ltwd_paragraph, ltw_mitigation_desc, ltwd_malware, ltw_mit_data = risk_assessment_instance.assign_lan_to_wan_domain_probability_score(selected_ltwd)
    wand_probability_score, wand_paragraph, wand_mitigation_desc, wand_malware, wand_mit_data = risk_assessment_instance.assign_wan_domain_probability_score(selected_wand)
    rad_score, rad_paragraph, rad_mitigation_description, rad_malware_desc, rad_mit_data = risk_assessment_instance.assign_remote_access_domain_probability_score(selected_rad)
    sad_probability_score, sad_paragraph, sad_mitigation_desc, sad_malware, sad_mit_data = risk_assessment_instance.assign_system_application_domain_probability_score(selected_sad)
    network_probability_score, network_paragraph, network_mitigation_description, network_malware, n_mit_data = risk_assessment_instance.assign_hacking_probability_score(selected_network_architecture)
    inventory_probability_score, inventory_paragraph, inventory_mitigation_description, i_malware, i_mit_data = risk_assessment_instance.assign_inventory_probability_score(selected_inventory)
    d_probability_score, d_paragraph, d_mitigation_description, d_malware, d_mit_data = risk_assessment_instance.assign_digital_assets_probability_score(selected_d)
    t_probability_score, t_paragraph, t_mitigation_description, t_malware, t_mit_data = risk_assessment_instance.assign_third_party_and_cloud_probability_score(selected_t)
    df_probability_score, df_paragraph, df_mitigation_description, df_malware, df_mit_data = risk_assessment_instance.assign_Data_flow_probability_score(selected_df)
    sp_probability_score, sp_paragraph, sp_mitigation_description, sp_malware, sp_mit_data = risk_assessment_instance.assign_security_policies_and_procedures_probability_score(selected_sp)
    pm_probability_score, pm_paragraph, pm_mitigation_description, pm_malware, pm_mit_data = risk_assessment_instance.assign_patch_managment_probability_score(selected_pm)
    md_probability_score, md_paragraph, md_mitigation_description, md_malware, md_mit_data = risk_assessment_instance.assign_monitoring_and_detection_probability_score(selected_md)
    ir_probability_score, ir_paragraph, ir_mitigation_description, ir_malware, ir_mit_data = risk_assessment_instance.assign_incident_response_probability_score(selected_ir)
    s_probability_score, s_paragraph, s_mitigation_description, s_malware, s_mit_data = risk_assessment_instance.assign_Social_Engineering_Testing_probability_score(selected_s)
    bl_probability_score, bl_paragraph, bl_mitigation_description, bl_malware, bl_mit_data = risk_assessment_instance.assign_Business_Location_probability_score(selected_bl)
    
    ud_mit_data_column = "\n".join(ud_mit_data)
    n_mit_data_column = "\n".join(n_mit_data)
    i_mit_data_column = "\n".join(i_mit_data)
    d_mit_data_column = "\n".join(d_mit_data)
    t_mit_data_column = "\n".join(t_mit_data)
    df_mit_data_column = "\n".join(df_mit_data)
    sp_mit_data_column = "\n".join(sp_mit_data)
    pm_mit_data_column = "\n".join(pm_mit_data)
    md_mit_data_column = "\n".join(md_mit_data)
    ir_mit_data_column = "\n".join(ir_mit_data)
    s_mit_data_column = "\n".join(s_mit_data)
    bl_mit_data_column = "\n".join(bl_mit_data)
    wd_mit_data_column = "\n".join(wd_mit_data)
    ld_mit_data_column = "\n".join(ld_mit_data)
    ltw_mit_data_column = "\n".join(ltw_mit_data)
    wand_mit_data_column = "\n".join(wand_mit_data)
    rad_mit_data_column = "\n".join(rad_mit_data)
    sad_mit_data_column = "\n".join(sad_mit_data)


    account_id = session['id']
    # Call the function to insert scores into user_scores table
    insert_user_scores(account_id, network_probability_score, inventory_probability_score, d_probability_score, t_probability_score, 
                       df_probability_score, sp_probability_score, pm_probability_score, md_probability_score, 
                       ir_probability_score, s_probability_score, bl_probability_score)


    return render_template('result.html',
                           network_score=network_probability_score,
                           network_paragraph=network_paragraph,
                           network_mitigation=network_mitigation_description,
                           network_malware = network_malware,
                           n_mit_data = n_mit_data_column,
                           inventory_score=inventory_probability_score,
                           inventory_paragraph=inventory_paragraph,
                           inventory_mitigation=inventory_mitigation_description,
                           i_malware = i_malware,
                           i_mit_data = i_mit_data_column,
                           d_score = d_probability_score,
                           d_paragraph = d_paragraph,
                           d_mitigation = d_mitigation_description,
                           d_malware = d_malware,
                           d_mit_data = d_mit_data_column,
                           t_score = t_probability_score,
                           t_paragraph = t_paragraph,
                           t_mitigation = t_mitigation_description,
                           t_malware = t_malware,
                           t_mit_data = t_mit_data_column,
                           df_score = df_probability_score,
                           df_paragraph = df_paragraph,
                           df_mitigation = df_mitigation_description,
                           df_malware = df_malware,
                           df_mit_data = df_mit_data_column,
                           sp_score = sp_probability_score,
                           sp_paragraph = sp_paragraph,
                           sp_mitigation = sp_mitigation_description,
                           sp_malware = sp_malware,
                           sp_mit_data = sp_mit_data_column,
                           pm_score = pm_probability_score,
                           pm_paragraph = pm_paragraph,
                           pm_mitigation = pm_mitigation_description,
                           pm_malware = pm_malware,
                           pm_mit_data = pm_mit_data_column,
                           md_score = md_probability_score,
                           md_paragraph = md_paragraph,
                           md_mitigation = md_mitigation_description,
                           md_malware = md_malware,
                           md_mit_data = md_mit_data_column,
                           ir_score = ir_probability_score,
                           ir_paragraph = ir_paragraph,
                           ir_mitigation = ir_mitigation_description,
                           ir_malware = ir_malware,
                           ir_mit_data = ir_mit_data_column,
                           s_score = s_probability_score,
                           s_paragraph = s_paragraph,
                           s_mitigation = s_mitigation_description,
                           s_malware = s_malware,
                           s_mit_data = s_mit_data_column,
                           bl_score = bl_probability_score,
                           bl_paragraph = bl_paragraph,
                           bl_mitigation = bl_mitigation_description,
                           bl_malware = bl_malware,
                           bl_mit_data = bl_mit_data_column,
                           ud_score = ud_probability_score,
                           ud_paragraph = ud_paragraph,
                           ud_mitigation = ud_mitigation_description,
                           ud_malware = ud_malware,
                           ud_mit_data = ud_mit_data_column,
                           wd_score = wd_score,
                           wd_paragraph = wd_paragraph,
                           wd_mitigation = wd_mitigation_description,
                           wd_malware = wd_malware_desc,
                           wd_mit_data = wd_mit_data_column,
                           ld_score = ld_probability_score,
                           ld_paragraph = ld_paragraph,
                           ld_mitigation = ld_mitigation_desc,
                           ld_malware = ld_malware,
                           ld_mit_data = ld_mit_data_column,
                           ltwd_score = ltwd_score,
                           ltwd_paragraph = ltwd_paragraph,
                           ltwd_mitigation = ltw_mitigation_desc,
                           ltwd_malware = ltwd_malware,
                           ltwd_mit_data = ltw_mit_data_column,
                           wand_score = wand_probability_score,
                           wand_paragraph = wand_paragraph,
                           wand_mitigation = wand_mitigation_desc,
                           wand_malware = wand_malware,
                           wand_mit_data = wand_mit_data_column,
                           rad_score = rad_score,
                           rad_paragraph = rad_paragraph,
                           rad_mitigation = rad_mitigation_description,
                           rad_malware = rad_malware_desc,
                           rad_mit_data = rad_mit_data_column,
                           sad_score = sad_probability_score,
                           sad_paragraph = sad_paragraph,
                           sad_mitigation = sad_mitigation_desc,
                           sad_malware = sad_malware,
                           sad_mit_data = sad_mit_data_column)
#http://127.0.0.1:5000/


@app.route('/view_scores')
def view_scores():
    if 'loggedin' in session:
        account_id = session['id']
        
        # Fetch scores of the logged-in user from the user_scores table
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user_scores WHERE account_id = %s", (account_id,))
        user_scores = cursor.fetchall()  # Fetch one row
        cursor.close()

        # Render the HTML template with scores
        if user_scores:  # Check if a row was fetched
            # Pass user_scores to the template 
            return render_template('view_scores.html', user_scores=user_scores)
        else:
            # No scores found for the user
            return render_template('view_scores.html', error="No scores found for the user.")
    else:
        return redirect(url_for('login'))
    

def search_attack_description(attack_id):
    file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
    df_m_s = pd.read_excel(file_path_mitigations)  
    filtered_df_ms = df_m_s[df_m_s['ID'] == attack_id]
    if not filtered_df_ms.empty:
        description = filtered_df_ms.iloc[0]['description']
        return description
    else:
        return "No match found for the provided attack ID."
    
@app.route('/search_attack_description', methods=['GET'])
def search_attack_description_route():
    attack_id = request.args.get('attack_id')
    description = search_attack_description(attack_id)
    return description



if __name__ == '__main__':
     app.run(debug=True)
    
    
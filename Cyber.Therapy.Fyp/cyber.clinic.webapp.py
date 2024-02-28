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
    
    def assign_Business_Industry_probability_score(self, Business_Industry):
    # Initialize default values
      probability_score_bi = None
      paragraph = None
      mitigation_description = None
      malware_description = None
      mit_data = []

      file_path = 'enterprise-attack-v13.1.xlsx'

    # Use if statements to assign scores based on the Business Industry
      if Business_Industry == "Finance" or Business_Industry == "Technology" or Business_Industry == "Manufacturing":
        probability_score_bi = 5
        if Business_Industry == "Finance":
           
           output_value = "The finance industry stands as a prime target for cyber risk due to its intrinsic reliance on digital infrastructure and vast reservoirs of valuable data. Financial institutions, including banks, investment firms, and insurance companies, are custodians of sensitive information, such as personal and financial data of individuals and businesses. This trove of data presents an irresistible allure to cybercriminals seeking illicit financial gain through various means, including identity theft, fraud, and extortion. Moreover, the interconnected nature of financial systems globally creates a ripple effect, wherein a breach in one institution can reverberate across the entire sector, leading to cascading financial losses and erosion of trust among consumers. As the finance industry embraces digital transformation and fintech innovations, the attack surface expands, offering cyber adversaries an ever-expanding array of vulnerabilities to exploit. Consequently, financial organizations must remain vigilant and continuously fortify their cybersecurity posture through robust defense mechanisms, threat intelligence, and proactive risk mitigation strategies to safeguard against the relentless onslaught of cyber threats."
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "Technology":
           
           output_value = "The technology industry is a prominent target for cyber risk owing to its pivotal role in driving innovation, digital transformation, and the global economy. As the engine behind the digital revolution, technology companies develop and maintain critical infrastructure, software platforms, and digital services that underpin modern society. However, this very ubiquity and interconnectedness make them lucrative targets for cybercriminals aiming to exploit vulnerabilities for financial gain, data theft, or disruption of operations. From cutting-edge startups to tech giants, no entity is immune to the evolving threat landscape characterized by sophisticated cyber attacks, including ransomware, supply chain compromises, and zero-day exploits. Moreover, the rapid pace of technological advancement often outpaces security measures, leaving organizations vulnerable to emerging threats and vulnerabilities. With the proliferation of Internet of Things (IoT) devices, cloud computing, and interconnected ecosystems, the attack surface expands exponentially, amplifying the risk landscape for technology companies. Consequently, safeguarding sensitive data, intellectual property, and digital assets becomes paramount, necessitating robust cybersecurity strategies, proactive threat intelligence, and collaboration across the industry to mitigate the pervasive cyber risks and ensure the resilience of technology-driven ecosystems."
           
           paragraph = output_value
           

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
        if Business_Industry == "Manufacturing":
           
           output_value = "The manufacturing industry is a prime target for cyber risk due to its critical role in global supply chains, production processes, and infrastructure. Manufacturers produce a wide array of goods ranging from consumer electronics to automobiles, often leveraging sophisticated industrial control systems (ICS), robotics, and Internet of Things (IoT) devices to optimize efficiency and productivity. However, the convergence of operational technology (OT) with information technology (IT) exposes manufacturing facilities to cyber threats that can disrupt operations, compromise sensitive data, and undermine product integrity. Cybercriminals target manufacturing firms to steal intellectual property, sabotage operations, or extort ransom payments, exploiting vulnerabilities in legacy systems, insecure network configurations, and lax cybersecurity protocols. Moreover, the increasing adoption of smart factories and interconnected supply chains introduces new vectors for cyber attacks, including supply chain compromises, ransomware attacks on production systems, and industrial espionage. As manufacturers embrace digital transformation initiatives such as Industry 4.0 and automation, securing digital assets, production lines, and critical infrastructure becomes imperative to safeguard against cyber threats and ensure business continuity. Robust cybersecurity measures, employee training, and collaboration with industry peers and cybersecurity experts are essential to mitigate cyber risks and protect the integrity and resilience of the manufacturing sector in an increasingly digitized and interconnected world."
           paragraph = output_value
           
           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
        return probability_score_bi, paragraph, mitigation_description, malware_description, mit_data


      elif Business_Industry == "Construction" or Business_Industry == "Consumer Goods and Services" or Business_Industry == "Transport":
        probability_score_bi = 3
        if Business_Industry == "Construction":
           
           output_value = "The construction industry faces significant cyber risks stemming from its reliance on digital technologies and interconnected systems for project management, design, and collaboration. As construction firms increasingly adopt Building Information Modeling (BIM), cloud-based project management platforms, and Internet of Things (IoT) devices, they become vulnerable to cyber threats that target sensitive project data, financial transactions, and critical infrastructure. Cybercriminals exploit vulnerabilities in construction software, weak network security, and the lack of cybersecurity awareness among employees to launch phishing attacks, ransomware campaigns, and business email compromise schemes. Moreover, the decentralized nature of construction projects, involving multiple stakeholders, subcontractors, and suppliers, complicates cybersecurity efforts and introduces additional points of entry for attackers. Construction firms are also susceptible to supply chain attacks, where malware is introduced through compromised third-party vendors or suppliers, posing a significant threat to project timelines and budgets. As the construction industry continues to digitize and embrace emerging technologies like Building Automation Systems (BAS) and Smart Buildings, robust cybersecurity measures, regular risk assessments, and employee training are essential to mitigate cyber risks, protect sensitive data, and ensure the integrity and safety of construction projects."

           
           paragraph = output_value
           

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "Consumer Goods and Services":
           
           output_value = "The consumer goods and services industry is increasingly targeted by cyber threats due to its widespread adoption of e-commerce platforms, digital payment systems, and customer data management solutions. With the rise of online shopping and the proliferation of connected devices, consumer goods companies are tasked with safeguarding vast amounts of sensitive customer information, including personal details, payment credentials, and purchase history. Cybercriminals exploit vulnerabilities in e-commerce websites, mobile applications, and supply chain networks to steal customer data, perpetrate fraudulent transactions, and launch ransomware attacks. Moreover, the interconnected nature of the global supply chain exposes consumer goods companies to supply chain risks, where malicious actors infiltrate third-party vendors or logistics partners to compromise product integrity or disrupt operations. The reputational damage resulting from data breaches or cyber incidents can significantly impact consumer trust and brand loyalty, leading to financial losses and long-term business consequences. To mitigate cyber risks, consumer goods and services companies must invest in robust cybersecurity measures, including encryption protocols, network monitoring systems, and employee awareness training, to protect customer data, preserve brand reputation, and ensure the resilience of their digital infrastructure in an evolving threat landscape."

           
           paragraph = output_value
           

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
              
        if Business_Industry == "Transport":
           
           output_value = "The transportation industry faces a myriad of cyber risks as it becomes increasingly reliant on digital technologies to manage operations and deliver services. From airlines and shipping companies to public transit systems and logistics providers, transportation networks are interconnected and vulnerable to cyber threats that can disrupt critical infrastructure, compromise passenger safety, and disrupt supply chains. Cyber attacks targeting transportation systems can range from ransomware attacks on airline reservation systems and maritime cargo tracking platforms to sophisticated cyber espionage campaigns aimed at stealing sensitive data related to flight schedules, freight manifests, and passenger manifests. Additionally, the proliferation of Internet of Things (IoT) devices and smart sensors in vehicles, aircraft, and railway systems introduces new entry points for cyber attackers to exploit vulnerabilities and gain unauthorized access to critical systems, posing risks of physical harm and operational disruption. To mitigate cyber risks in the transportation sector, organizations must implement robust cybersecurity measures, including network segmentation, intrusion detection systems, and regular security audits, to safeguard infrastructure, protect passenger data, and ensure the reliability and safety of transportation services in an increasingly digitalized world."

           
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
        return probability_score_bi, paragraph, mitigation_description, malware_description, mit_data
      elif Business_Industry == "Government/Military Organisations" or Business_Industry == "Energy production" or Business_Industry == "SMEs" or Business_Industry == "Agriculture":
        probability_score_bi = 4
        if Business_Industry == "Government/Military Organisations":
           
           output_value = "Government and military organizations are prime targets for cyber threats due to the sensitive nature of the information they handle and the critical services they provide. Cyber attacks against government and military entities can have far-reaching consequences, including compromising national security, undermining public trust, and disrupting essential services. Threat actors, ranging from nation-states to cybercriminal organizations and hacktivist groups, actively target government networks to steal classified information, conduct espionage, manipulate public opinion, and disrupt government operations. These attacks encompass a wide range of tactics, including phishing, malware infections, denial-of-service (DoS) attacks, and supply chain compromises. Furthermore, the interconnectedness of government systems and the reliance on third-party vendors for essential services increase the attack surface and complexity of defending against cyber threats. As governments continue to digitize their operations and embrace emerging technologies such as cloud computing and Internet of Things (IoT), the need for robust cybersecurity measures, stringent regulations, and collaboration between public and private sectors becomes increasingly critical to safeguarding sensitive data, preserving national security, and maintaining the integrity of democratic institutions."

           
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "Energy Production":
           
           output_value = "The energy production industry is a critical infrastructure sector that plays a vital role in powering economies and supporting essential services. However, it is also a prime target for cyber threats due to its interconnected infrastructure, reliance on industrial control systems (ICS), and the potential impact of disruptions. Cyber attacks against energy production facilities can result in significant consequences, including power outages, environmental damage, and economic losses. Threat actors, including nation-states, cybercriminals, and hacktivist groups, target energy infrastructure to disrupt operations, steal sensitive information, and cause widespread chaos. These attacks can take various forms, such as ransomware attacks on energy grids, sabotage of power plants through malware infections, and espionage to gain access to critical systems. The increasing digitization and integration of smart technologies into energy networks further amplify the cybersecurity risks. Therefore, robust security measures, continuous monitoring, and collaboration between industry stakeholders and government agencies are essential to safeguarding energy production infrastructure, ensuring resilience against cyber threats, and maintaining the stability of global energy supply."

           
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "SMEs":
           
           output_value = "Small and Medium-sized Enterprises (SMEs) are increasingly becoming targets for cyber threats due to several factors. While large corporations often have substantial cybersecurity resources and expertise, SMEs typically lack the same level of preparedness, making them vulnerable to attacks. Cybercriminals perceive SMEs as lucrative targets because they may hold valuable data, such as customer information or intellectual property, yet have fewer security defenses in place. Additionally, SMEs often rely on third-party vendors and cloud services, introducing additional security risks. Common cyber threats faced by SMEs include phishing scams, ransomware attacks, and supply chain compromises. The impact of a successful cyber attack on an SME can be devastating, leading to financial losses, reputational damage, and even business closure. Therefore, it is essential for SMEs to prioritize cybersecurity measures, including employee training, regular software updates, and data backup strategies, to mitigate the risks posed by cyber threats."

           
           paragraph = output_value
           

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "Agriculture":
           output_value = "The agriculture industry is becoming a target for cyber threats due to its growing reliance on technology and digital systems. As modern farming practices incorporate IoT devices, automation, and data analytics, agricultural operations have become more interconnected and vulnerable to cyber attacks. Threat actors, including cybercriminals and state-sponsored groups, target agricultural organizations to steal valuable data such as crop yields, pricing information, and trade secrets. These attacks can disrupt supply chains, compromise sensitive data, and result in financial losses for farmers and businesses. Furthermore, vulnerabilities in agricultural technologies, such as precision farming equipment and agricultural drones, can be exploited by attackers to gain unauthorized access and control over critical infrastructure. As the agriculture sector continues to digitize and adopt emerging technologies, it is essential for farmers and agricultural businesses to prioritize cybersecurity measures, including network security, data encryption, and employee training, to protect against cyber threats and safeguard the integrity of food production systems."
  
           paragraph = output_value


           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "
        return probability_score_bi, paragraph, mitigation_description, malware_description, mit_data

      elif Business_Industry == " Accommodation" or Business_Industry == "Education":
        probability_score_bi = 2
        if Business_Industry == "Accommodation":
           output_value = "The accommodation industry, encompassing hotels, resorts, and lodging facilities, faces significant cyber risks due to the vast amount of personal and financial data collected from guests during reservations and stays. Cyber attacks targeting accommodation businesses can result in the exposure of sensitive customer information, such as credit card details, passport numbers, and contact information, leading to financial losses and reputational damage. Threat actors, including cybercriminals and hackers, exploit vulnerabilities in reservation systems, guest Wi-Fi networks, and payment processing platforms to steal valuable data, perpetrate fraud, and launch ransomware attacks. Moreover, the interconnected nature of hospitality operations, with multiple touchpoints spanning online booking platforms, property management systems, and IoT-enabled devices, increases the attack surface and complexity of defending against cyber threats. As the hospitality sector continues to embrace digital transformation and adopt technologies like mobile check-in, smart room controls, and personalized guest experiences, the need for robust cybersecurity measures, employee training, and regulatory compliance becomes paramount to safeguarding guest privacy, maintaining trust, and preserving the integrity of accommodation businesses."
      
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        if Business_Industry == "Education":
           output_value = "The education sector faces significant cybersecurity challenges due to its reliance on technology for teaching, research, and administrative functions. Educational institutions store vast amounts of sensitive information, including student records, financial data, and research findings, making them attractive targets for cybercriminals seeking to steal personal information, commit fraud, or disrupt operations. Cyber attacks against educational organizations can result in data breaches, intellectual property theft, financial losses, and reputational damage. Threat actors, including hackers, ransomware groups, and state-sponsored actors, exploit vulnerabilities in outdated systems, weak authentication mechanisms, and human error to gain unauthorized access to networks, exfiltrate data, or deploy malware. Common attack vectors include phishing emails targeting staff and students, ransomware attacks encrypting critical files, and Distributed Denial of Service (DDoS) attacks disrupting online learning platforms. As educational institutions increasingly adopt digital technologies such as cloud computing, mobile devices, and Internet-connected devices (IoT), the need for robust cybersecurity measures, user awareness training, and incident response capabilities becomes paramount to safeguarding sensitive data, protecting academic integrity, and ensuring uninterrupted access to educational resources."
  
           paragraph = output_value

           if probability_score_bi > 2:
            # Load the Excel file into a Pandas DataFrame for mitigations
             df_m = pd.read_excel(file_path, 'mitigations')
             df_m_s = pd.read_excel(file_path, 'software') 
             mitre_attack_data = MitreAttackData("enterprise-attack.json")

            # Define search terms for mitigations
             search_terms_m = ['detection', 'sensitive', 'data']

            # Combine search terms using '|', which represents logical OR
             search_pattern_m = '|'.join(search_terms_m)

             # Filter rows where the "description" column contains any of the search terms
             filtered_df_m = df_m[df_m['description'].str.contains(search_pattern_m, case=False)]
             filtered_df_ms = df_m_s[df_m_s['description'].str.contains(search_pattern_m, case=False)]
             mitigation_stix_id = "course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c"
             attacks_mitigated_by_m1031 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

            # Check if there are any matching rows for mitigations
             if not filtered_df_m.empty:
                # Output the values from the "description" column of all matching rows as a proper paragraph
                output_values_m = filtered_df_m.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                s_values = filtered_df_ms.apply(lambda row: f"{row['ID']}: {row['description']}", axis=1).tolist()
                mitigation_description = '\n'.join(output_values_m)
                malware_description = '\n'.join(s_values)

                for t in attacks_mitigated_by_m1031:
                    technique = t["object"]
                    mit_data.append(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")
           else:
                mitigation_description = "No mitigation descriptions available."
                malware_description = "No malware noted"
                mit_data = " "

        return probability_score_bi, paragraph, mitigation_description, malware_description, mit_data
      
      return probability_score_bi, paragraph, mitigation_description, malware_description, mit_data

    def assign_hacking_probability_score(self, network_architecture):
    # Initialize the default score
     probability_score_h = None
     paragraph_d = None
     mitigation_description = None
     malware_description = None
     paragraph = None
     mit_data = []
     file_path = 'enterprise-attack-v13.1.xlsx'

    # Use if statements to assign scores based on the network architecture
     if network_architecture == "Zero Trust Architecture (ZTA)" or network_architecture == "Microsegmented Network":
        probability_score_h = 1
        if network_architecture == "Zero Trust Architecture (ZTA)":
            description = "Zero Trust Architecture (ZTA) is challenging for hackers to breach due to its comprehensive and layered security approach. Unlike traditional security models that rely on perimeter-based defenses, ZTA operates on the principle of assuming that no entity, whether internal or external, should be trusted by default. This means that every user, device, and application must undergo rigorous verification and authentication processes before being granted access to resources. Additionally, ZTA emphasizes continuous monitoring and strict access controls, constantly scrutinizing network activity and ensuring that only authorized users and devices are allowed to interact with sensitive data or systems. Even if an attacker manages to breach one layer of defense, they would still face multiple other security measures, such as encryption, micro-segmentation, and least privilege access policies, before gaining access to critical assets. This multi-layered approach significantly increases the complexity and difficulty for hackers attempting to infiltrate the network, making ZTA a robust and effective cybersecurity solution."
            paragraph_d = description
        else:
            description = "Microsegmented Network architecture is another formidable challenge for hackers due to its granular segmentation of network traffic. This approach divides the network into smaller segments or zones, each with its own set of security policies and access controls. By isolating different parts of the network, microsegmentation limits the lateral movement of attackers, preventing them from easily traversing between segments even if they manage to compromise one. Additionally, microsegmentation allows for more precise control over traffic flow, enabling organizations to enforce stricter security measures based on specific criteria such as user roles, device types, or application requirements. This means that even if an attacker gains access to one segment, they would still need to overcome additional security barriers to reach their target, reducing the overall risk of a successful breach. With its fine-grained security controls and isolation capabilities, microsegmentation adds another layer of defense to the network, making it harder for hackers to exploit vulnerabilities and compromise sensitive data or systems."
            paragraph_d = description
     elif network_architecture == "Network Access Control (NAC)":
        probability_score_h = 2
        description = "Network Access Control (NAC) is a vital security measure that helps safeguard networks from unauthorized access and potential security threats. NAC works by enforcing policies that determine which devices or users are allowed to connect to the network and what level of access they are granted based on factors such as user identity, device type, and security posture. By verifying the identity and compliance of devices and users before granting access, NAC helps prevent unauthorized access and reduces the risk of malware infections and other security incidents. Additionally, NAC provides continuous monitoring and enforcement of security policies, ensuring that only authorized devices and users remain connected to the network. This proactive approach to network security helps organizations maintain control over their network infrastructure and protect against a wide range of cyber threats."
        paragraph_d = description
     elif network_architecture == "Distributed Networks" or network_architecture == "Complex Network Topologies":
        probability_score_h = 3
        if network_architecture == "Distributed Networks":
          description = "Distributed networks can be both more resilient and more prone to cyber attacks compared to centralized architectures, depending on their implementation and management. While distributing resources across multiple nodes can increase complexity and make it harder for attackers to compromise the entire system, it also introduces new attack vectors and challenges. The increased number of nodes and communication channels can create more entry points for attackers, and maintaining consistent security policies across all nodes can be challenging. Additionally, distributed networks may rely on vulnerable communication protocols and inter-node connections, making them susceptible to interception or tampering attacks. Targeted attacks on specific nodes or components, such as DDoS attacks or malware infections, can also pose significant threats. Overall, while distributed networks offer benefits in resilience and scalability, they require careful planning, robust security measures, and ongoing monitoring to effectively mitigate the increased risk of cyber attacks."
          paragraph_d = description
        elif network_architecture == "Complex Network Topologies":
          description = "Complex network topologies, characterized by intricate arrangements of nodes and connections, present both advantages and vulnerabilities in terms of cybersecurity. While their intricate nature can enhance resilience by dispersing resources and responsibilities, it also introduces new avenues for cyber attacks. The multitude of nodes and interconnections in complex network topologies can create numerous entry points for attackers to exploit, potentially leading to widespread compromises. Moreover, maintaining consistent security measures across all components of the network can be challenging, increasing the risk of misconfigurations or overlooked vulnerabilities. Additionally, the reliance on diverse communication protocols and inter-node links may introduce weaknesses susceptible to interception or manipulation by malicious actors. Targeted attacks, such as DDoS assaults or malware infiltrations, can capitalize on the complexity of network topologies to disrupt operations or compromise sensitive data. Thus, while complex network topologies offer benefits in terms of resilience and scalability, they necessitate meticulous planning, robust security protocols, and continuous monitoring to effectively mitigate cyber threats."
          paragraph_d = description
     elif network_architecture == "Flat Perimeter Networks":
        probability_score_h = 4
        description = "Flat perimeter networks, characterized by a simplified architecture where all devices are connected to a single network segment without internal segmentation or access controls, present significant vulnerabilities to cyber attacks. In such networks, there is often a lack of segregation between different types of devices and users, making it easier for attackers to move laterally once they gain access to the network. This lack of segmentation also means that a breach at one point in the network can potentially compromise the entire infrastructure, as there are no barriers to limit the spread of malware or unauthorized access. Additionally, without proper access controls and monitoring mechanisms, it can be challenging to detect and respond to suspicious activity effectively. As a result, flat perimeter networks are highly susceptible to various cyber threats, including malware infections, data breaches, and unauthorized access attempts. To improve security, organizations should implement measures such as network segmentation, access controls, and monitoring tools to create multiple security zones and better protect their infrastructure from cyber attacks."
        paragraph_d = description
     elif network_architecture == "Legacy Systems" or network_architecture == "Bring Your Own Device Networks" or network_architecture == "None":
        probability_score_h = 5
        if network_architecture == "Legacy Systems":
          description = "Legacy systems, which are outdated or obsolete technologies that may still be in use within an organization's IT infrastructure, pose significant cybersecurity risks due to their inherent vulnerabilities and limited support for security updates. These systems often lack modern security features and may contain known vulnerabilities that have not been patched or addressed by vendors. As a result, they are attractive targets for attackers seeking to exploit weaknesses and gain unauthorized access to sensitive data or critical systems. Moreover, legacy systems may not be compatible with newer security tools and protocols, making it challenging for organizations to adequately protect them against evolving threats. Additionally, because legacy systems are often interconnected with newer technologies, a compromise of a legacy system can potentially lead to widespread security breaches across the entire network. To mitigate the risks associated with legacy systems, organizations should prioritize upgrading or replacing outdated technologies, implementing compensating security controls, and regularly assessing and monitoring the security posture of these systems."
          paragraph_d = description
        elif network_architecture == "Bring Your Own Device Networks": 
          description = "Bring Your Own Device (BYOD) networks, where employees use their personal devices (such as smartphones, laptops, or tablets) to access corporate resources and data, present unique cybersecurity challenges. While BYOD policies can increase flexibility and productivity, they also introduce significant risks to corporate networks and sensitive information. Personal devices may not have the same level of security controls or protections as company-owned devices, making them more vulnerable to malware infections, data breaches, and unauthorized access. Moreover, BYOD networks blur the lines between personal and corporate data, complicating data management and compliance efforts. Additionally, the diversity of devices and operating systems within a BYOD environment can make it challenging for IT teams to enforce consistent security policies and configurations across all devices. To mitigate the risks associated with BYOD networks, organizations should implement robust security measures such as device encryption, remote wipe capabilities, mobile device management (MDM) solutions, and network access controls. They should also educate employees about cybersecurity best practices and the importance of maintaining the security of their personal devices when accessing corporate resources."
          paragraph_d = description
        elif network_architecture == "None":
          description = "If an organization lacks a defined network architecture, it becomes highly susceptible to cyber attacks due to the absence of structured security measures and controls. Without a network architecture in place, there is no clear delineation of network boundaries or segmentation, making it easier for attackers to gain unauthorized access to sensitive systems and data. Additionally, the absence of security policies and protocols leaves the network vulnerable to various threats, including malware infections, phishing attacks, and data breaches. Furthermore, without proper network architecture, there is limited visibility and control over network traffic, making it challenging to detect and respond to security incidents effectively. Ultimately, the absence of a network architecture significantly increases the organization's exposure to cyber attacks and compromises its overall cybersecurity posture."
          paragraph_d = description 
     if probability_score_h == 1 or probability_score_h == 2 or probability_score_h == 3 or probability_score_h == 4 or probability_score_h == 5:
           
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
     return probability_score_h, paragraph_d, paragraph, mitigation_description, malware_description, mit_data
    
    def assign_inventory_probability_score(self, inventory):
        # Initialize the default score
     probability_score_i = None
     mitigation_description = None
     malware_description = None
     paragraph_d = None
     paragraph = None
     mit_data = []

    # Use if statements to assign scores based on the network architecture
     if inventory == "Air-gapped systems" or inventory == "IOT":
        probability_score_i = 3
        if inventory == "Air-gapped systems":
          description = "Even though air-gapped systems are physically isolated from external networks and disconnected from the internet, they are not immune to cyber attacks. While the absence of network connectivity reduces the attack surface, air-gapped systems remain vulnerable to insider threats, physical access attacks, and various covert channels for data exfiltration. Insider threats can exploit their physical proximity to the system to introduce malware or manipulate data, compromising the integrity and confidentiality of the system. Additionally, malicious actors can target air-gapped systems through infected USB drives, removable media, or other peripheral devices introduced by authorized personnel or unwitting individuals. Moreover, sophisticated attack techniques, such as acoustic, electromagnetic, or optical covert channels, can be used to bypass the air gap and exfiltrate sensitive information from the system. Thus, while air-gapped systems provide a higher level of security against remote cyber attacks, they still require robust physical security measures, strict access controls, and continuous monitoring to mitigate the risk of insider threats and covert channels infiltration."
          paragraph_d = description
        elif inventory == "IOT":
          description = "If you have Internet of Things (IoT) devices in your home or workplace, you are at risk of cyber attacks due to the inherent vulnerabilities associated with these connected devices. IoT devices, such as smart thermostats, security cameras, and wearable devices, often lack robust security features and may have default passwords that are easily guessable or hardcoded, making them susceptible to exploitation by attackers. Additionally, many IoT devices have limited processing power and memory, making it difficult to install security updates or patches to address known vulnerabilities. Furthermore, because IoT devices are connected to the internet and often interact with other devices and systems, a compromise of one device can potentially lead to the infiltration of the entire network, resulting in data breaches, privacy violations, and disruption of services. To mitigate the risks associated with IoT devices, it is essential to regularly update firmware, change default passwords, segment IoT devices from the main network, and implement network-level security measures such as firewalls and intrusion detection systems."
          paragraph_d = description
     elif inventory == "Physical Servers":
        probability_score_i = 4
        paragraph_d = "If an organization relies on physical servers for its IT infrastructure, it is exposed to various cybersecurity risks and vulnerabilities. Physical servers are susceptible to theft, tampering, and physical damage, which can compromise the confidentiality, integrity, and availability of data and services. Attackers may exploit vulnerabilities in the server hardware or operating system to gain unauthorized access, manipulate data, or launch denial-of-service attacks. Additionally, physical servers often require regular maintenance and updates, during which security patches may not be applied promptly, leaving them vulnerable to known exploits. Furthermore, if physical servers are not adequately protected within a secure data center environment, they may be vulnerable to environmental threats such as power outages, natural disasters, or physical intrusion. To mitigate these risks, organizations should implement robust physical security measures, regularly update and patch server software, and consider transitioning to virtualized or cloud-based server solutions that offer enhanced security features and scalability."  
     elif inventory == "Obsolete systems":
        probability_score_i = 5
        paragraph_d = "If you have obsolete systems within your network infrastructure, you are at heightened risk of cyber attacks due to several factors. Obsolete systems often lack support from vendors, meaning they no longer receive security updates or patches to address known vulnerabilities. Consequently, these systems are more susceptible to exploitation by threat actors seeking to infiltrate your network. Without the latest security measures in place, obsolete systems may serve as easy entry points for attackers, allowing them to breach your network and compromise sensitive data or critical systems. Furthermore, as obsolete systems may not be compatible with modern security tools and protocols, it becomes challenging to effectively monitor and defend against cyber threats. Additionally, the interconnected nature of networks means that a compromise of an obsolete system can potentially impact the security of the entire network, further amplifying the risk. Thus, it is crucial to prioritize the upgrade or replacement of obsolete systems to mitigate the cybersecurity risks they pose."  
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

     return probability_score_i, paragraph_d, paragraph, mitigation_description, malware_description, mit_data
    
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
    selected_ind = request.form.get('business_industry')
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
    ind_probability_score, ind_paragraph, ind_mitigation_description, ind_malware, ind_mit_data = risk_assessment_instance.assign_Business_Industry_probability_score(selected_ind)
    network_probability_score, n_description, network_paragraph, network_mitigation_description, network_malware, n_mit_data = risk_assessment_instance.assign_hacking_probability_score(selected_network_architecture)
    inventory_probability_score, i_description, inventory_paragraph, inventory_mitigation_description, i_malware, i_mit_data = risk_assessment_instance.assign_inventory_probability_score(selected_inventory)
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
    ind_mit_data_column = "\n".join(ind_mit_data)
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
                           ind_score = ind_probability_score,
                           ind_paragraph = ind_paragraph,
                           ind_mitigation = ind_mitigation_description,
                           ind_malware = ind_malware,
                           ind_mit_data = ind_mit_data_column,
                           network_score=network_probability_score,
                           n_description = n_description,
                           network_paragraph=network_paragraph,
                           network_mitigation=network_mitigation_description,
                           network_malware = network_malware,
                           n_mit_data = n_mit_data_column,
                           inventory_score=inventory_probability_score,
                           i_description = i_description,
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
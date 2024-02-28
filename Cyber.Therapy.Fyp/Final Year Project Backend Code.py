
def assign_inventory_probability_score(inventory):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if inventory == "Air-gapped systems" or inventory == "IOT":
        probability_score = 3
    elif inventory == "Physical Servers":
        probability_score = 4
    elif inventory == "Obsolete systems":
        probability_score = 5
    else:
        return "Please enter a Valid entry."

    return probability_score

# Get the network architecture from the user
inventory = input("Enter the company's inventory: ")

# Call the function to assign the hacking probability score
probability_score_res = assign_inventory_probability_score(inventory)

# Print the assigned hacking probability score
print(probability_score_res )

def assign_digital_assets_probability_score(digital_asset):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if digital_asset == "Non-Critical information":
        probability_score = 1
    elif digital_asset == "Customer Lists":
        probability_score = 2
    elif digital_asset == "User Credentials" or digital_asset == "Employee Records":
        probability_score = 3
    elif digital_asset == "Intellectual Property" or digital_asset == "Employee Records" or digital_asset == "Cryptocurrencies" or digital_asset == "Supplychains" or digital_asset == "Customer Communication Systems":
        probability_score = 4
    elif digital_asset == "Sensitive and Financial Data" or digital_asset == "Healthcare Records" or digital_asset == "Government data" or digital_asset == " Industrial Control Systems(ICS)" or digital_asset == "Product designs" or digital_asset == " Critical Infrastructure":
        probability_score = 5 
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
digital_asset = input("Enter the company's Digital assets: ")

# Call the function to assign the hacking probability score
probability_score_res2 = assign_digital_assets_probability_score(digital_asset)

# Print the assigned hacking probability score
print(probability_score_res2 )

def assign_third_party_and_cloud_probability_score(third_part_and_cloud_services):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if third_part_and_cloud_services == "Private Cloud or managed cloud" or third_part_and_cloud_services == "Risk Management Programs":
        probability_score = 1
    elif third_part_and_cloud_services == "Software as a service" or third_part_and_cloud_services == "Auto Scaling to foreign servers":
        probability_score = 2
    elif third_part_and_cloud_services == "Third-Party Data Providers" or third_part_and_cloud_services == "Third party Research and Development Data":
        probability_score = 3
    elif third_part_and_cloud_services == "Data managed locally" or third_part_and_cloud_services == "No cloud":
        probability_score = 5
    else:
        return "Enter valid entry."

    return probability_score

# Get the network architecture from the user
third_part_and_cloud_services = input("Enter the company's Third Party Services: ")

# Call the function to assign the hacking probability score
probability_score_res3 = assign_third_party_and_cloud_probability_score(third_part_and_cloud_services)

# Print the assigned hacking probability score
print(probability_score_res3 )

def assign_Data_flow_probability_score(Data_flow):
    # Initialize the default score
    probability_score = None


    if Data_flow == "Role-Based Access Controls(RBAC)" or Data_flow == "VPNs":
        probability_score = 1
    elif Data_flow == "Data Loss Prevention (DLP) System Implemented":
        probability_score = 2
    elif Data_flow == "HeaNet filesender" or Data_flow == "SSH File Transfer Protocols":
        probability_score = 3
    elif Data_flow == "Managed Work/Staff emails, eg Outlook":
        probability_score = 4
    elif Data_flow == "Personal emails" or Data_flow == "None":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
Data_flow = input("Enter the company's Data Flow methods: ")

# Call the function to assign the hacking probability score
probability_score_res4 = assign_Data_flow_probability_score(Data_flow)

# Print the assigned hacking probability score
print(probability_score_res4)

def assign_security_policies_and_procedures_probability_score(security_policies_and_procedures):
    # Initialize the default score
    probability_score = None

    
    if security_policies_and_procedures == "Security Awareness and Training Policy" or security_policies_and_procedures == "Vendor and Third-Party Security Policy" or security_policies_and_procedures == "Data Classification and Handling Policy" or security_policies_and_procedures =="Access Control Policy, Password Policy" or security_policies_and_procedures == "Acceptable Use Policy":
        probability_score = 1
    elif security_policies_and_procedures == "Most policies applied but no awarness training":
        probability_score = 2
    elif security_policies_and_procedures == "Remote Work and BYOD Policy if start-up if fulltime online":
        probability_score = 3
    elif security_policies_and_procedures == "Only one policy applied eg Bring Your Own Device (BYOD) Policy only":
        probability_score = 4
    elif security_policies_and_procedures == security_policies_and_procedures == "None":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
security_policies_and_procedures = input("Enter the company's Security policies: ")

# Call the function to assign the hacking probability score
probability_score_res5 = assign_security_policies_and_procedures_probability_score(security_policies_and_procedures)

# Print the assigned hacking probability score
print(probability_score_res5)

def assign_patch_managment_probability_score(patch_managment):
    # Initialize the default score
    probability_score = None

    
    if patch_managment == "Manual Patch Management":
        probability_score = 4
    if patch_managment == "Outsourced Patch Management ":
        probability_score = 3
    elif patch_managment == "Automated Patch Management" or patch_managment == "Cloud-Based Patch Management" or patch_managment == "Patch as a Service (PaaS)" or patch_managment == "Security Information and Event Management (SIEM) Integration":
        probability_score = 2
    elif patch_managment == "Vulnerability Management" or patch_managment == "DevOps-Integrated Patching" or patch_managment == "Risk-Based Patch Management":
        probability_score = 1
    if patch_managment == "No Software Patch Management":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
patch_managment = input("Enter the company's Software Patch managment system: ")

# Call the function to assign the hacking probability score
probability_score_res6 = assign_patch_managment_probability_score(patch_managment)

# Print the assigned hacking probability score
print(probability_score_res6)

def assign_monitoring_and_detection_probability_score(monitoring_and_detection):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if monitoring_and_detection == "Security Information and Event Management (SIEM)" or monitoring_and_detection == "Endpoint Detection and Response (EDR)" or monitoring_and_detection == "File Integrity Monitoring (FIM)" or monitoring_and_detection =="Security Orchestration, Automation, and Response (SOAR)":
        probability_score = 2
    elif monitoring_and_detection == "Intrusion Detection System (IDS)" or monitoring_and_detection == "Network Traffic Analysis (NTA)" or monitoring_and_detection == "User and Entity Behavior Analytics (UEBA)" or monitoring_and_detection == "Anomaly Detection" or monitoring_and_detection == "Log Management":
        probability_score = 3
    elif monitoring_and_detection == "None":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
monitoring_and_detection = input("Enter the company's monitoring and Detection methodes: ")

# Call the function to assign the hacking probability score
probability_score_res7 = assign_monitoring_and_detection_probability_score(monitoring_and_detection)

# Print the assigned hacking probability score
print(probability_score_res7)

def assign_incident_response_probability_score(incident_response):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if incident_response == "Continuous Improvement of Systems" or incident_response == "Proactive Incident Response Plan" or incident_response == "Integrating systems with Security Operations":
        probability_score = 1
    elif incident_response == "Playbook-Based Incident Response" or incident_response == "Tabletop Exercises" or incident_response == "Automation-Driven Incident Response" or incident_response == "Cloud-Centric Incident Response":
        probability_score = 2
    elif incident_response == "Collaborative Incident Response" or incident_response == "Communication and Public Relations Integration" or incident_response == "Regulatory Compliance Adherence":
        probability_score = 3
    elif incident_response == "None":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
incident_response = input("Enter the company's incedent response plans: ")

# Call the function to assign the hacking probability score
probability_score_res8 = assign_incident_response_probability_score(incident_response)

# Print the assigned hacking probability score
print(probability_score_res8)

def assign_Social_Engineering_Testing_probability_score(Social_Engineering_Testing):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if Social_Engineering_Testing == "Almost all techniques listed applied - Phishing Simulations, Vishing (Voice Phishing), Smishing (SMS Phishing), Impersonation Testing, Baiting (Physical Media Drops), USB Drop Tests, Tailgating Tests":
        probability_score = 2
    elif Social_Engineering_Testing == "None":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
Social_Engineering_Testing = input("Enter the company's: ")

# Call the function to assign the hacking probability score
probability_score_res9 = assign_Social_Engineering_Testing_probability_score(Social_Engineering_Testing)

# Print the assigned hacking probability score
print(probability_score_res9)

def assign_Business_Location_probability_score(Business_Location):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if Business_Location == "Latin America" or Business_Location == "Africa" or Business_Location =="Middle East":
        probability_score = 2
    elif Business_Location == "North America":
        probability_score = 3
    elif Business_Location == "Europe":
        probability_score = 4
    elif Business_Location == "Asia":
        probability_score = 5
    else:
        return "Please enter a valid entry."

    return probability_score

# Get the network architecture from the user
Business_Location = input("Enter the company's location: ")

# Call the function to assign the hacking probability score
probability_score_resX = assign_Business_Location_probability_score(Business_Location)

# Print the assigned hacking probability score
print(probability_score_resX)

def assign_hacking_probability_score(network_architecture):
    # Initialize the default score
    probability_score = None

    # Use if statements to assign scores based on the network architecture
    if network_architecture == "Zero Trust Architecture (ZTA)" or network_architecture == "Microsegmented Network":
        probability_score = 1
    elif network_architecture == "Network Access Control (NAC)":
        probability_score = 2
    elif network_architecture == "Distributed Networks" or network_architecture == "Complex Network Topologies":
        probability_score = 3
    elif network_architecture == "Flat Perimeter Networks":
        probability_score = 4
    elif network_architecture == "Legacy Systems" or network_architecture == "Bring Your Own Device Networks" or network_architecture == "None":
        probability_score = 5
    else:
        return "Network architecture not recognized. Please enter a valid network architecture."

    return probability_score

# Get the network architecture from the user
network_architecture = input("Enter the company's Network Architecture: ")

# Call the function to assign the hacking probability score
probability_score_resXI = assign_hacking_probability_score(network_architecture)

# Print the assigned hacking probability score
print(probability_score_resXI)

user = User.query.filter_by(username=username).first()
   
    user.network_score = network_probability_score
    user.inventory_score = inventory_probability_score
    user.digital_assets_score = d_probability_score
    user.thirdparty_score = t_probability_score
    user.dataflow_score = df_probability_score
    user.security_policies_score = sp_probability_score
    user.patch_score = pm_probability_score
    user.monitoring_and_detection_score = md_probability_score
    user.incident_response_score = ir_probability_score
    user.social_engineering_testing = s_probability_score
    user.business_location = bl_probability_score

    db.session.commit()


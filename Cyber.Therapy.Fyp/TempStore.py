def display_mitigation_network_description(self, probability_score_h):
        if probability_score_h > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['Architect']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_inventory_description(self, probability_score_i):
        if probability_score_i > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['servers']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)

    def display_mitigation_digital_description(self, probability_score_d):
        if probability_score_d > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['sensitive data']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_third_party_description(self, probability_score_thp):
        if probability_score_thp > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['services']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_data_flow_description(self, probability_score_df):
        if probability_score_df > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['file']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_SP_description(self, probability_score_spp):
        if probability_score_spp > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['user']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_Patch_description(self, probability_score_pm):
        if probability_score_pm > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['update']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
         
    def display_mitigation_monitoring_description(self, probability_score_md):
        if probability_score_md > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['detection']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)

    def display_mitigation_incident_resp_description(self, probability_score_ir):
        if probability_score_ir > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['store']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)
      
    def display_mitigation_Social_Eng_description(self, probability_score_see):
        if probability_score_see > 2:
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations')  

            search_terms = ['social']
            search_pattern = '|'.join(search_terms)

            filtered_df_m = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df_m.empty:
                output_values = filtered_df_m['description'].tolist()
                paragraph_m = '\n'.join(output_values)
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, paragraph_m)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
        else:
            self.mitigation_text.delete(1.0, tk.END)


    def display_mitigation_description(self, probability_score_info):
     if probability_score_info['probability_score'] and probability_score_info['probability_score'] > 2:
        # Process the collected probability score information
            probability_score = probability_score_info['probability_score']
            file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
            df_m = pd.read_excel(file_path_mitigations, 'mitigations') 
            score_results = []

            #Network
            search_terms_h = ['Architect']
            search_pattern_h = '|'.join(search_terms_h)

            #Inventory
            search_terms_i = ['servers']
            search_pattern_i = '|'.join(search_terms_i)

            #Digital Assets
            search_terms_d = ['sensitive data']
            search_pattern_d = '|'.join(search_terms_d)

            #Third Part
            search_terms_thp = ['services']
            search_pattern_thp = '|'.join(search_terms_thp)

            #data flow
            search_terms_df = ['file']
            search_pattern_df = '|'.join(search_terms_df)
            
            #Security Procedures
            search_terms_spp = ['user']
            search_pattern_spp = '|'.join(search_terms_spp)

            #Security Procedures
            search_terms_pm = ['update']
            search_pattern_pm = '|'.join(search_terms_pm)

            #Security incident Responce
            search_terms_ir = ['store']
            search_pattern_ir = '|'.join(search_terms_ir)

            #Social Eng
            search_terms_see = ['social']
            search_pattern_see = '|'.join(search_terms_see)

            #Monitoring and detect
            search_terms_md = ['detection']
            search_pattern_md = '|'.join(search_terms_md)

             #Business Location
            search_terms_bl = ['detection']
            search_pattern_bl = '|'.join(search_terms_bl)


     for widget_name, widget_info in self.widgets_dict.items():
            search_terms = widget_info["search_terms"]
            search_pattern = '|'.join(search_terms)

            #make this for each term
            filtered_df_h = df_m[df_m['description'].str.contains(search_pattern_h, case=False)]
            filtered_df_i = df_m[df_m['description'].str.contains(search_pattern_i, case=False)]
            filtered_df_d = df_m[df_m['description'].str.contains(search_pattern_d, case=False)]
            filtered_df_thp = df_m[df_m['description'].str.contains(search_pattern_thp, case=False)]
            filtered_df_df = df_m[df_m['description'].str.contains(search_pattern_df, case=False)]
            filtered_df_spp = df_m[df_m['description'].str.contains(search_pattern_spp, case=False)]
            filtered_df_pm = df_m[df_m['description'].str.contains(search_pattern_pm, case=False)]
            filtered_df_ir = df_m[df_m['description'].str.contains(search_pattern_ir, case=False)]
            filtered_df_see = df_m[df_m['description'].str.contains(search_pattern_see, case=False)]
            filtered_df_md = df_m[df_m['description'].str.contains(search_pattern_md, case=False)]
            filtered_df_bl = df_m[df_m['description'].str.contains(search_pattern_bl, case=False)]

   
            if not filtered_df_h.empty:
                widget_name = widget_info["widget"].get()
                #make for each score
                output_values_h = filtered_df_h['description'].tolist()
                paragraph_h = '\n'.join(output_values_h)

                output_values_i = filtered_df_i['description'].tolist()
                paragraph_i = '\n'.join(output_values_i)

                output_values_d = filtered_df_d['description'].tolist()
                paragraph_d = '\n'.join(output_values_d)

                output_values_thp = filtered_df_thp['description'].tolist()
                paragraph_thp = '\n'.join(output_values_thp)

                output_values_df = filtered_df_df['description'].tolist()
                paragraph_df = '\n'.join(output_values_df)

                output_values_spp = filtered_df_spp['description'].tolist()
                paragraph_spp = '\n'.join(output_values_spp)

                output_values_pm = filtered_df_pm['description'].tolist()
                paragraph_pm = '\n'.join(output_values_pm)

                output_values_ir = filtered_df_ir['description'].tolist()
                paragraph_ir = '\n'.join(output_values_ir)

                output_values_see = filtered_df_see['description'].tolist()
                paragraph_see = '\n'.join(output_values_see)

                output_values_md = filtered_df_md['description'].tolist()
                paragraph_md = '\n'.join(output_values_md)

                output_values_bl = filtered_df_bl['description'].tolist()
                paragraph_bl = '\n'.join(output_values_bl)

                #make append for each score
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_h}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_i}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_d}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_thp}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_df}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_spp}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_pm}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_ir}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_see}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_md}\n\n")
                score_results.append(f"{widget_name}:\nProbability Score: {probability_score}\n Mitre Suggested Mitigations:\n{paragraph_bl}\n\n")
                

                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, score_results)
            else:
                self.mitigation_text.delete(1.0, tk.END)
                self.mitigation_text.insert(tk.END, "No match found in the 'description' column.")
     else:
            self.mitigation_text.delete(1.0, tk.END)


        def display_mitigation_description(self, probability_score_info):
     if probability_score_info['probability_score'] and probability_score_info['probability_score'] > 2:
        probability_score = probability_score_info['probability_score']
        file_path_mitigations = 'enterprise-attack-v13.1.xlsx'
        df_m = pd.read_excel(file_path_mitigations, 'mitigations')
        score_results = []

        search_terms_mapping = {
            'Architect': ['Architect'],
            'servers': ['servers'],
            'sensitive data': ['sensitive data'],
            'services': ['services'],
            'file': ['file'],
            'user': ['user'],
            'update': ['update'],
            'store': ['store'],
            'social': ['social'],
            'detection': ['detection'],
            'business location': ['detection']  # Adjust the actual term for Business Location
         }

        for label_text, widget_info in self.widgets_dict.items():
            selected_option = widget_info["widget"].get()
            function = widget_info["function"]
            probability_score, output_values = function(selected_option)

            # Get the corresponding search terms based on the label_text
            search_terms = search_terms_mapping.get(label_text, [])
            search_pattern = '|'.join(search_terms)

            filtered_df = df_m[df_m['description'].str.contains(search_pattern, case=False)]

            if not filtered_df.empty:
                output_values = filtered_df['description'].tolist()
                paragraph = '\n'.join(output_values)
                score_results.append(
                    f"{label_text}:\nProbability Score: {probability_score}\nMitre Suggested Mitigations:\n{paragraph}\n\n")
            else:
                score_results.append(f"{label_text}:\nNo match found in the 'description' column.\n\n")

        # Display all results in the text widget
        self.mitigation_text.delete(1.0, tk.END)
        self.mitigation_text.insert(tk.END, ''.join(score_results))
     else:
        self.mitigation_text.delete(1.0, tk.END)

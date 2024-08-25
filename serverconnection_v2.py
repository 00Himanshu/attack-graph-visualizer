import mysql.connector


class MYSQL_connection:
    def __init__(self):
        self.total_paths = []
        self.mydb = mysql.connector.connect(user='ron', password='root',
                                            host='127.0.0.1',
                                            database='attack_graph_v2')
        print(self.mydb)
        self.mycursor = self.mydb.cursor()

    # finding attacks in the same asset
    def find_in_asset_vulnerability(self, asset_id, current_access):
        if current_access == 'low':
            self.mycursor.execute(f"SELECT precondition.vulnerability from precondition "
                                  f"where precondition.required_access = '{current_access}' and "
                                  f"precondition.connection_type is NULL and "
                                  f"precondition.vulnerability in (SELECT vulnerability.cve_id from vulnerability where vulnerability.asset_type = '{self.find_asset_type(asset_id)}')")

        else:
            self.mycursor.execute(f"SELECT precondition.vulnerability from precondition "
                                  f"where precondition.connection_type is NULL and "
                                  f"precondition.vulnerability in (SELECT vulnerability.cve_id from vulnerability where vulnerability.asset_type = '{self.find_asset_type(asset_id)}')")

        vulnerabilities = self.mycursor.fetchall()
        vulnerabilities = [i[0] for i in vulnerabilities]
        vulnerabilities = [[f'{asset_id}.{current_access}',f'{asset_id}.{i}'] for i in vulnerabilities]
        return vulnerabilities

    # finding attack out of the asset -> means affecting connected asset
    def find_out_of_asset_vulnerabilities(self, asset_id, current_access):
        a = []
        for i in self.find_connections(asset_id):
            for j in self.find_asset_vulnerability(self.find_asset_type(i[0])):
                if j in self.find_precondition_with_datas(current_access, i[1]):
                    # print([f'{asset_id}.{current_access}', f'{asset_id}.{i[1]}.{i[0]}', f'{i[0]}.{j}'])
                    a.append([f'{asset_id}.{current_access}', f'{asset_id}.{i[1]}.{i[0]}', f'{i[0]}.{j}'])
        if len(a) > 0:
            return a
        else:
            return []

    def find_asset_type(self, asset_id):
        self.mycursor.execute(f"SELECT assets.asset_type from assets where assets.asset_id = '{asset_id}'")
        return self.mycursor.fetchone()[0]
    
    # finding the SCORE OF THE Vulnerability
    def find_score(self,asset_id,vulnerability):
        self.mycursor.execute(f'SELECT P.cve_score from (SELECT assets.asset_id,vulnerability.cve_id,vulnerability.cve_score from assets INNER JOIN vulnerability on assets.asset_type = vulnerability.asset_type) P where P.asset_id = "{asset_id}" and P.cve_id = "{vulnerability}"')
        return self.mycursor.fetchone()[0]
    
    def find_mitre_attack_id(self,asset_id,vulnerability):
        self.mycursor.execute(f'SELECT P.mitre_attack_id from (SELECT assets.asset_id,vulnerability.cve_id,vulnerability.cve_score,vulnerability.mitre_attack_id from assets INNER JOIN vulnerability on assets.asset_type = vulnerability.asset_type) P where P.asset_id = "{asset_id}" and P.cve_id = "{vulnerability}"')
        return self.mycursor.fetchone()[0]

    def find_mitre_defend_id(self,asset_id,vulnerability):
        self.mycursor.execute(f'SELECT P.mitre_defend_id from (SELECT assets.asset_id,vulnerability.cve_id,vulnerability.cve_score, vulnerability.mitre_defend_id from assets INNER JOIN vulnerability on assets.asset_type = vulnerability.asset_type) P where P.asset_id = "{asset_id}" and P.cve_id = "{vulnerability}"')
        return self.mycursor.fetchone()[0]


    def find_connections(self, current_asset_id):
        self.mycursor.execute(f"SELECT connections.destination_asset , connections.connection_type from connections "
                              f"where connections.source_asset = '{current_asset_id}'")
        return self.mycursor.fetchall()  # fetching a 2d list having the desitionation connection along with the
        # connection type

    def find_asset_vulnerability(self, current_asset_type):
        self.mycursor.execute(
            f"SELECT vulnerability.cve_id from vulnerability WHERE vulnerability.asset_type = '{current_asset_type}'")
        l1 = [i[0] for i in self.mycursor.fetchall()]
        return l1

    def find_precondition_with_datas(self, current_access, connection_type):
        if current_access.lower() == 'low':
            self.mycursor.execute(f"SELECT precondition.vulnerability FROM precondition where ("
                                  f"precondition.required_access is NULL or precondition.required_access = 'low') and "
                                  f"precondition.connection_type = '{connection_type}'")
            l1 = [i[0] for i in self.mycursor.fetchall()]
        else:
            self.mycursor.execute(f"SELECT precondition.vulnerability FROM precondition "
                                  f"where precondition.connection_type = '{connection_type}'")
            l1 = [i[0] for i in self.mycursor.fetchall()]
        return l1

    


    #finding post condition after attack
    def find_post_condition(self,attack):
        # print(attack)
        current_node , vulnerability = attack.split('.')
        # print(current_node,attack)
        self.mycursor.execute(f"SELECT postcondition.gained_access from postcondition where postcondition.cve_id = '{vulnerability}'")
        return current_node,self.mycursor.fetchone()[0]

    # back tracking code

    # In asset Back tracking code
    def in_asset_back_tracking(self,asset_id,current_access):
        in_asset_back_tracking_list = []
        self.mycursor.execute(f"select precondition.required_access, precondition.vulnerability from precondition where precondition.vulnerability in (select vulnerability.cve_id from vulnerability where vulnerability.asset_type = (SELECT assets.asset_type from assets WHERE assets.asset_id = '{asset_id}') and vulnerability.cve_id in(SELECT postcondition.cve_id from postcondition where postcondition.gained_access ='{current_access}')) and precondition.connection_type is NULL;")
        for i in self.mycursor.fetchall():
            in_asset_back_tracking_list.append([f'{asset_id}.{i[0].lower()}',f'{asset_id}.{i[1]}'])
        return in_asset_back_tracking_list

    # out_of_asset_backtracking
    def out_of_asset_back_tracking(self,asset_id,current_access):
        self.mycursor.execute(f"select * from precondition where precondition.vulnerability in (select vulnerability.cve_id from vulnerability where vulnerability.asset_type = (SELECT assets.asset_type from assets WHERE assets.asset_id = '{asset_id}') and vulnerability.cve_id in(SELECT postcondition.cve_id from postcondition where postcondition.gained_access ='{current_access}')) and precondition.connection_type is not  NULL;")
        out_asset_back_tracking_list = []
        for i in self.mycursor.fetchall():
            self.mycursor.execute(f"SELECT connections.source_asset from connections where connections.destination_asset = '{asset_id}' and connections.connection_type = '{i[1]}';")
            for j in self.mycursor.fetchall():
                if i[0] == None:
                    out_asset_back_tracking_list.append([f'{j[0]}.high',f'{j[0]}.{i[1]},{asset_id}',f'{asset_id}.{i[2]}'])
                    out_asset_back_tracking_list.append([f'{j[0]}.low',f'{j[0]}.{i[1]},{asset_id}',f'{asset_id}.{i[2]}'])
                else:
                    out_asset_back_tracking_list.append([f'{j[0]}.{i[0].lower()}',f'{j[0]}.{i[1]},{asset_id}',f'{asset_id}.{i[2]}'])
        return out_asset_back_tracking_list
    
    
    # from here starts the server mini connection for data retrival
    def show_assets(self):
        self.mycursor.execute('SELECT assets.asset_id,assets.asset_type from assets')
        data = [f'{i[0]} - {i[1]}' for i in self.mycursor.fetchall()]

        return data


############################################################################
############################################################################



    def show_criticality_assets(self):
        self.mycursor.execute('SELECT assets.asset_id,assets.asset_type,assets.importance_score from assets')
        data = [{"asset":f"{i[0]}","asset_type":f"{i[1]}","asset_importance_score":i[2]} for i in self.mycursor.fetchall()]
        
        return data

    def show_asset_importance_score(self,asset_id):
        self.mycursor.execute(f'SELECT assets.importance_score from assets where assets.asset_id = "{asset_id}"')
        return self.mycursor.fetchone()[0]
    

if __name__ == '__main__':
    x = MYSQL_connection()
    print(x.find_in_asset_vulnerability('A1','low'))
    print(x.find_out_of_asset_vulnerabilities('A1','high'))
    print(x.find_post_condition('A7.CVE-2012-2749'))

    # print(x.find_in_asset_vulnerability('low', 'windows 7'))
    # met_attack_condition = x.find_out_of_asset_vulnerabilities('A2','high')
    # print(met_attack_condition)
    # print(x.find_post_condition(met_attack_condition[0][2]))
    # print(x.find_asset_type('a2'))
    print(x.in_asset_back_tracking('A1','high'))
    print(x.out_of_asset_back_tracking('A7','high'))
    # print(x.find_score('A7','CVE-2006-3486'))
    print(x.show_asset_importance_score('A3'))
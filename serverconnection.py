import re
import mysql.connector



class MyCursor_Operation:
    def __init__(self) -> None:
        self.mydb = mysql.connector.connect(user='ron', password='root',
                              host='127.0.0.1',database = 'attack-graph')
        print(__name__,self.mydb)

        self.mycursor = self.mydb.cursor()

    def show_CVE(self): # gives all the cve id from cve data in my sql
        self.mycursor.execute('SELECT cve_id from cve_data ORDER BY cve_id')
        data = self.mycursor.fetchall()
        data = [i[0] for i in data] # converting to list for easier translation
        return data

    def get_description(self,cve_id): # gives corresponding description to cve id
        self.mycursor.execute(f"SELECT description from cve_data WHERE cve_id = '{cve_id}'")
        return self.mycursor.fetchone()[0]

    def get_cve_information(self,cve_id): # gives the cve information
        self.mycursor.execute(f"SELECT * from cve_data WHERE cve_id = '{cve_id}'")
        return self.mycursor.fetchall()[0]


    def get_attack_information(self,attack_id): # gives attack information for attack node
        self.mycursor.execute(f'SELECT * from attack_data where attack_id="{attack_id}"')
        return self.mycursor.fetchall()[0]

    def get_attacks(self,cve_id): # get attacks from precondition to attack
        self.mycursor.execute(f'select attack_id from or_logic_attack_map where cve_id = "{cve_id}"')
        return [ i[0] for i in self.mycursor.fetchall()]
        # return mycursor.fetchall()

    def get_posconditions(self,attack_id): # get the cve ids for postcondition
        self.mycursor.execute(f"select cve_id from attack_postcondition where attack_id = '{attack_id}'")
        return [i[0] for i in self.mycursor.fetchall()]



#only for testing
if __name__ == '__main__':
    testing = MyCursor_Operation()
    print(testing.show_CVE())
    print(testing.get_attack_information('attack_001'))
    print(testing.get_cve_information('CVE-2022-20722'))
    print(testing.get_posconditions('attack_005'))




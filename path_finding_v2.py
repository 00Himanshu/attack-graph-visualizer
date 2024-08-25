from serverconnection_v2 import MYSQL_connection


class Path_Finder:
    def __init__(self):
        self.unique_nodes = []
        self.server = MYSQL_connection()
        self.main_list = []
        self.naming_directory = {}

    def find_all_path(self, asset_id, current_access, travelled_path):
        if f'{asset_id}.{current_access}' in travelled_path:
            if travelled_path[:-1] not in self.main_list:
                self.main_list.append(travelled_path[:-1])
            return

        else:
            # getting in asset attacks
            travelled_path += (f'{asset_id}.{current_access}',)
            # finding in aseet attacks as path in DFS
            for i in self.server.find_in_asset_vulnerability(asset_id, current_access):
                asset_id_in, current_access_in = self.server.find_post_condition(i[1])
                path = travelled_path + (i,)
                self.find_all_path(asset_id_in, current_access_in, path)

            # finding out of asset attacks as path in DFS
            for j in self.server.find_out_of_asset_vulnerabilities(asset_id, current_access):
                asset_id_out, current_access_out = self.server.find_post_condition(j[2])
                path = travelled_path + (j,)
                self.find_all_path(asset_id_out, current_access_out, path)

    def get_unique_nodes(self):
        self.unique_nodes = []
        for i in self.main_list:
            for j in i:
                if j not in self.unique_nodes:
                    self.unique_nodes.append(j)

    def convert_to_unique_names(self):
        for i in self.unique_nodes:
            if type(i) == list:
                self.naming_directory[f'{i[0]}.{i[-1]}'] = i
            else:
                self.naming_directory[i] = i

    def name_conversion(self, node):
        for i in self.naming_directory:
            if self.naming_directory[i] == node:
                return i

    def get_path(self, asset_id, current_access):
        empty_tuple = ()
        self.find_all_path(asset_id, current_access, empty_tuple)
        self.get_unique_nodes()
        self.convert_to_unique_names()
        print('Unique nodes print: ',self.unique_nodes)
        print('naming directory: ',self.naming_directory)
        a_dictionary = {}
        for i in self.unique_nodes:
            empty_list = []
            for j in range(len(self.main_list)):
                for k in range(len(self.main_list[j])-1):
                    if i == self.main_list[j][k]:
                        if self.name_conversion(self.main_list[j][k+1]) not in empty_list:
                            empty_list.append(self.name_conversion(self.main_list[j][k+1]))
            a_dictionary[self.name_conversion(i)] = empty_list
        return self.naming_directory, a_dictionary
    
    # back tracked path
    def find_back_tracked_path(self,asset_id,current_access,travelled_path):
        
        if f'{asset_id}.{current_access}' in travelled_path:
            print('ending',travelled_path)
            self.main_list.append(travelled_path[:-1])
            return
        travelled_path += (f'{asset_id}.{current_access}',)
        print('travelling : ',travelled_path)
        # In asset Back tracking tree
        for i in self.server.in_asset_back_tracking(asset_id,current_access):
            path = travelled_path + (i,)
            asset_id_in,current_access_in = i[0].split('.')
            self.find_back_tracked_path(asset_id_in,current_access_in,path)
        
        # Out asset Back Tracking tree
        for j in self.server.out_of_asset_back_tracking(asset_id,current_access):
            path = travelled_path + (j,)
            asset_id_out,current_access_out = j[0].split('.')
            self.find_back_tracked_path(asset_id_out,current_access_out,path)
        
        if not self.server.in_asset_back_tracking(asset_id,current_access) and not self.server.out_of_asset_back_tracking(asset_id,current_access):
            self.main_list.append(travelled_path)


    def get_back_tracked_path(self,asset_id,current_access):
        travelled_path = ()
        self.find_back_tracked_path(asset_id,current_access,travelled_path)
        print('***********************')
        for i in self.main_list:
            print(i)
        for i in range(len(self.main_list)):
            self.main_list[i] = self.main_list[i][::-1]
        print('Reverse *********************************\n\n')
        for i in self.main_list:
            print(i)
        self.get_unique_nodes()
        self.convert_to_unique_names()
        print('Unique nodes print: ',self.unique_nodes)
        print('naming directory: ',self.naming_directory)
        a_dictionary = {}
        for i in self.unique_nodes:
            empty_list = []
            for j in range(len(self.main_list)):
                for k in range(len(self.main_list[j])-1):
                    if i == self.main_list[j][k]:
                        if self.name_conversion(self.main_list[j][k+1]) not in empty_list:
                            empty_list.append(self.name_conversion(self.main_list[j][k+1]))
            a_dictionary[self.name_conversion(i)] = empty_list
        return self.naming_directory, a_dictionary
    



if __name__ == '__main__':
    x = Path_Finder()
    x.find_all_path('A1','low',())
    # x_1, y = x.get_path(asset_id='A1', current_access='low')

    # print('OUTPUTTTTTTTTTTTTTTTTTTTTTT')
    # print(x_1)
    # print('DICTIONARY OF PATH ')
    # print(y)

    # print('\n\n')
    # for i in x:
    #     print(i)
    # for i in y:
    #     print(i)
    a,b = x.get_back_tracked_path('A14','high')
    print(f'Naming DIRECTORY ************** \n{a}\n*******path OUTPUT **************** \n{b}')
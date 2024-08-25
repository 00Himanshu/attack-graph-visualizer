from serverconnection_v2 import MYSQL_connection
from typing import Union

f = open('./paths_checking.txt',mode='a')

server = MYSQL_connection()


class Node:
    #node is simple object that hold the data which are needed
    def __init__(self,node_id : str, access_level : str):
        
        self.node_id = node_id
        self.node_type = server.find_asset_type(node_id)
        self.node_importance_score = server.show_asset_importance_score(node_id)
        self.access_level = access_level
        self.distance_from_start = 9999
        self.distance_to_goal = 0
        self.color = None

    def __repr__(self) -> str:
        return f'{self.node_id} + {self.access_level}'
    
    def give_id(self):
        return f'{self.node_id}.{self.access_level}'
    
    def give_name(self):
        return self.give_id()
    
    def give_style(self):
        if self.color == None:

            return {'shape': 'circle', 'background-color': 'yellow'}
        else:
            return {'shape': 'circle', 'background-color': f'{self.color}'}
        
    def give_table_data(self):
        return {"Asset Type" : self.node_type,
                "Access Level": self.access_level}
    

    def give_description(self):
        return f'Node ID = {self.node_id}Node_type = {self.node_type}Node Importance Score in the Network = {self.node_importance_score}Node distance from start = {self.distance_from_start}'


class Vulnerability_node:
    def __init__(self,from_asset : Union[Node , str],to_asset : Union[Node , str],vulnerability_id : str,connection_type: str = None):
        self.node_name = f'{str(from_asset)}+{str(to_asset)}+{vulnerability_id}'
        self.from_asset = from_asset
        self.to_asset = to_asset
        self.connection_type = connection_type
        self.vulnerability_id = vulnerability_id
        self.importance_score_of_goal = None
        self.vulnerabilty_score = server.find_score(to_asset.node_id,vulnerability_id)
        self.distance_from_start = 9999
        self.distance_to_goal = 0
        self.impact_score = None
        self.criticality_score = None # added for getting criticality score
        self.color = None
        self.mitre_attack_id = server.find_mitre_attack_id(to_asset.node_id,vulnerability_id)
        self.mitre_defend_id = server.find_mitre_defend_id(to_asset.node_id,vulnerability_id) 



    def __repr__(self) -> str:
        if self.connection_type == None:
            return str({'Attack type': 'IN ASSET ATTACK','from':str(self.from_asset),'to':str(self.to_asset),'vulnerability used':self.vulnerability_id})
        else:
            return str({'Attack type': 'OUT OF ASSET ATTACK','from':str(self.from_asset),'to':str(self.to_asset),'vulnerability used':self.vulnerability_id,'Connection':self.connection_type})

    def give_id(self):
        return f'{self.from_asset.give_id()}.{self.to_asset.give_id()}.{self.vulnerability_id}'
    
    def give_name(self):
        return f'{self.vulnerability_id}'
    
    def give_style(self):
        if self.color == None:
            return {'shape': 'rectangle', 'background-color': '#87CEEB'}
        else:
            return {'shape': 'rectangle', 'background-color': self.color}
    
    # calculating criticality and impact score both
    def calculate_criticality(self):
        try:
            self.criticality_score = self.importance_score_of_goal /self.distance_to_goal
            self.impact_score = self.criticality_score / self.distance_from_start
        except:
            print(self.__repr__, ' HAS ISSUE')

    def give_table_data(self):
        return {'CVE ID' : self.vulnerability_id, 
                'CVSS Score' : self.vulnerabilty_score,
                 'Mitre Attack ID' : self.mitre_attack_id,
                  'Mitre Defend ID' : self.mitre_defend_id }
    
    # gives description that will be shown to JSON FILE
    def give_description(self):
        return f'From asset = {self.from_asset.node_id} <br>TO asset = {self.to_asset.node_id} <br>Node distance from start = {self.distance_from_start} <br>Node Distance to Goal = {self.distance_to_goal}<br>Node vulnerability score = {self.vulnerabilty_score}<br>Node Ciricality score = {self.criticality_score}<br>Node impact score = {self.impact_score}'

class NodeList:
    def __init__(self):
        self.goal_asset_importance_score = None
        self.asset_nodes = []
        self.vulnerability_nodes = []

    def create_asset_node(self,asset_id:str,access_level: str):
        for i in self.asset_nodes:
            if i.node_id == asset_id and i.access_level == access_level:
                return i
        else:
            some_variable = Node(node_id=asset_id,access_level=access_level)
            self.asset_nodes.append(some_variable)
            return some_variable
    
    def create_vulnerability_node(self, from_asset: Union[Node, str], to_asset: Union[Node, str], vulnerability_id: str,connection_type: str = None):
        for i in self.vulnerability_nodes:
            if i.from_asset == from_asset and i.to_asset == to_asset and i.vulnerability_id == vulnerability_id and i.connection_type == connection_type:
                return i
        else:
            some_variable =  Vulnerability_node(from_asset=from_asset,
                                        to_asset=to_asset,
                                        vulnerability_id=vulnerability_id,
                                        connection_type=connection_type)
            some_variable.importance_score_of_goal = self.goal_asset_importance_score
            self.vulnerability_nodes.append(some_variable)
            return some_variable



class Json_node_builder:
    
    def __init__(self) -> None:
        self.parent_count = 0
        self.parent_node_dict = {}
    
    def list_to_node(self,adjacency_matrix):
        
        nodes = []
        for i in adjacency_matrix:

            # give_id gives unique names to node can be used for connection also
            nodes.append({'data':{'id':f'{i.give_id()}',
                                'name':f'{i.give_name()}',
                                'description':f'{i.give_description()}',
                                'table_data': i.give_table_data()},
                          'css': i.give_style(),})
        connection = 0
        for i in adjacency_matrix:
            for j in adjacency_matrix[i]:
                nodes.append({'data' : {'id' : f'X{connection}',
                                        'source' : i.give_id(),
                                        'target' : j.give_id(),
                                        'directed' : 'true'}})
                connection +=1
        
        return nodes



'''
Critical path finder main

IN USE :down
'''
class Find_ciritical_path:
    def __init__(self) -> None:
        self.myserver = MYSQL_connection()
        self.main_list = []
        self.node = NodeList()
        self.adjacency_dictionary = {}
        self.unique_nodes = []
        self.number = 0

    def check_if_in(self, node: Node, path: Union[tuple, list]):
        for i in path:
            if str(node) == str(i):
                return True
        else:
            return False
    
    def set_distance_from_start(self,node : Union[Node, Vulnerability_node], distance : int):

        if node.distance_from_start > distance:
            node.distance_from_start = distance
        

    def find_ciritical_path(self, current_node: Node, goal_node: Node, travelling_path: tuple, distance : int = 0):
        # if self.check_if_in(current_node, travelling_path):
        if current_node in travelling_path:
            # print('done')
            # self.main_list.append(travelling_path[:-1])
            return
        else:
            self.set_distance_from_start(current_node , distance= distance + 1)
            if current_node == goal_node:
                travelling_path += (current_node,)
                # print('here')
                self.main_list.append(travelling_path)
                return
            travelling_path +=(current_node,)
            try:
                # for i in travelling_path[-1:-4:-1]:
                #     print(id(i) , end = ',')
                # print('\n\n')
                f.write(f'{str(travelling_path)}\n')
                print('',end=f'{self.number}\r')
                self.number += 1
            except:
                pass
            # try:
            #     print(travelling_path[-2])
            # except:
            #     print(travelling_path[-1])

            for i in self.myserver.find_in_asset_vulnerability(current_node.node_id, current_node.access_level):
                # print('here',i)
                asset_id_in, current_access_in = self.myserver.find_post_condition(i[1])
                # print(asset_id_in,current_access_in)
                new_node = self.node.create_asset_node(asset_id_in, current_access_in)

                vulnerability_id = i[1].split('.')[1]
                
                vulnerability_node = self.node.create_vulnerability_node(current_node, new_node, vulnerability_id)
                self.set_distance_from_start(vulnerability_node, distance + 2)

                path = travelling_path + (vulnerability_node,)
                # print(new_node,goal_node,path)
                self.find_ciritical_path(new_node, goal_node, path,distance=distance+2)

            for j in self.myserver.find_out_of_asset_vulnerabilities(current_node.node_id, current_node.access_level):
                
                # reference what the data is in J
                # [['A1.high', 'A1.remote_access.A3', 'A3.CVE-2019-12749']]
                # kindly follow and update the upper data to get the 
                asset_id_out, current_access_out = self.myserver.find_post_condition(j[2])
                # print(asset_id_out,current_access_out)
                new_node = self.node.create_asset_node(asset_id_out, current_access_out)
                vulnerability_id = j[2].split('.')[1]
                connection_type = j[1].split('.')[1]
                vulnerability_node = self.node.create_vulnerability_node(current_node, new_node,
                                                            vulnerability_id=vulnerability_id,
                                                            connection_type=connection_type)
                self.set_distance_from_start(vulnerability_node,distance + 2)
                path = travelling_path + (vulnerability_node,)
                self.find_ciritical_path(new_node, goal_node, path,distance=distance+2)

    
    
    def get_unique_nodes(self):
        return self.node.asset_nodes

    def list_to_adjacency_matrix(self):
        self.adjacency_dictionary = {}
        self.unique_nodes = []
        self.unique_nodes = self.node.asset_nodes + self.node.vulnerability_nodes
        # for i in self.unique_nodes:
        #     print(i)
        for i in self.unique_nodes:
            empty_list = []
            for j in range(len(self.main_list)):
                for k in range(len(self.main_list[j])-1):
                    if i == self.main_list[j][k]:
                        if self.main_list[j][k+1] not in empty_list:
                            empty_list.append(self.main_list[j][k+1])
            self.adjacency_dictionary[i] = empty_list

    def calculate_shortest_path_to_target(self,start,end):
        from shortest_path_finding import BFS_SP
        shortest_path = BFS_SP(self.adjacency_dictionary,start,end)
        return shortest_path
    
        


    # total PIPE lINE OF THE FLOW IS WRITTEN HERE

    # This methods takes the input directly from the ROUTE.PY
    # and gives NODE OUTPUT
    # also error is made here



    def get_critical_path(self, asset_id, current_access, goal_asset_id, goal_access_level):
        empty_tuple = ()
        starting_node = self.node.create_asset_node(asset_id, current_access)
        goal_node = self.node.create_asset_node(goal_asset_id, goal_access_level)
        self.node.goal_asset_importance_score = goal_node.node_importance_score
        # 1. First its trying to find the path by using network
        # while finding path it also create nodes with value ** distance from start
        self.find_ciritical_path(current_node=starting_node, goal_node=goal_node, travelling_path=empty_tuple)
        if len(self.main_list) == 0:

            # if no path is found then return 0 which will return an error page

            print(f'NO path FOUND for {starting_node} to {goal_node}')
            return 0

        print('PATHS FOUND ',len(self.main_list))
        print(self.main_list)
        print('time taken ', self.number)

        # 2. creating adjacency matrix from 2D list
        self.list_to_adjacency_matrix()

        # 3. calculate shortest distance to goal

        # self.calculate_shortest_path_to_target(goal_node=goal_node)

        # 4. now calculate the criticality score and impact score 
        for i in self.node.vulnerability_nodes:
            i.calculate_criticality()

        # three_most_connected_nodes = sorted(self.adjacency_dictionary,key=lambda x:len(self.adjacency_dictionary[x]),reverse=True)[:3]
        # most_vulnerabilities = []
        # for i in self.adjacency_dictionary:
        #     if any(item in three_most_connected_nodes for item in self.adjacency_dictionary[i]):
        #         most_vulnerabilities.append(i)

        # most_vulnerabilities.sort(key= lambda x: x.vulnerabilty_score,reverse=True)

        # # three_most_connected_nodes[0].color = '#FF0000'
        # # three_most_connected_nodes[1].color = '#FF5733'
        # # three_most_connected_nodes[2].color = '#FFA07A'
        
        # most_vulnerabilities[0].color = '#FF0000'
        # most_vulnerabilities[1].color = '#FF5733'
        # try:
        #     most_vulnerabilities[2].color = '#FFA07A'
        # except:
        #     pass

        
        safe_nodes =[starting_node,goal_node]
        temp_nodes = list(self.adjacency_dictionary.keys()) # strong temp nodes
        for i in temp_nodes:
            if len(self.adjacency_dictionary[i]) == 0 and i not in safe_nodes:
                self.adjacency_dictionary.pop(i)
        # 4. create JSON FROM THE DATA AND RETURN IT TO ROUTE.PY
        json_converter = Json_node_builder()
        json_return = json_converter.list_to_node(self.adjacency_dictionary)

        print(goal_node)
        variable = self.calculate_shortest_path_to_target(starting_node,goal_node)
        for i in range(0,len(variable)-1):
            for j in json_return:
                try:
                    if j['data']['source'] == variable[i].give_id() and j['data']['target'] == variable[i+1].give_id():
                        j['css'] = {'line-color': 'red'}
                except:
                    pass
        return json_return







# previous class DON'T need any development


'''NO DEVELOPMENT ZONE '''
class Find_critical_path_string_type:
    def __init__(self) -> None:
        self.main_list = []
        self.myserver = MYSQL_connection()
        self.number = 0

    def find_critical_path(self,current_node: str,goal_node:str,travelling_path: tuple):
        if current_node in travelling_path:
            return
        else:
            if current_node == goal_node:
                travelling_path += (current_node,)
                print(travelling_path)
                self.main_list.append(travelling_path)
                return
            # extract asset_id and current access from the string
            asset_id = current_node.split('.')[0]
            # print(current_node.split('.'))
            current_access = current_node.split('.')[1]
            travelling_path += (current_node,)

            print("",end=f'{self.number}\r')
            self.number += 1
            for i in self.myserver.find_in_asset_vulnerability(asset_id, current_access):
                asset_id_in, current_access_in = self.myserver.find_post_condition(i[1])
                path = travelling_path + (i,)
                self.find_critical_path(current_node=f'{asset_id_in}.{current_access_in}',goal_node=goal_node,travelling_path=path)

            # finding out of asset attacks as path in DFS
            for j in self.myserver.find_out_of_asset_vulnerabilities(asset_id, current_access):
                asset_id_out, current_access_out = self.myserver.find_post_condition(j[2])
                path = travelling_path + (j,)
                self.find_critical_path(current_node=f'{asset_id_out}.{current_access_out}',goal_node=goal_node,travelling_path=path)

    
    
    def get_critical_path(self, asset_id, current_access, goal_asset_id, goal_access_level):
        empty_tuple = ()
        starting_node = f'{asset_id}.{current_access}'
        print(starting_node)
        goal_node = f'{goal_asset_id}.{goal_access_level}'
        print(goal_node)

        self.find_critical_path(current_node=starting_node,goal_node = goal_node,travelling_path=empty_tuple)
        print(self.main_list)
        print('time taken',self.number)



class Find_attack_range:
    def __init__(self) -> None:
        self.myserver = MYSQL_connection()
        self.main_list = []
        self.node = NodeList()
        self.adjacency_dictionary = {}
        self.unique_nodes = []
        self.number = 0

    def find_all_attackable_path(self,current_node : Node, travelling_path : tuple):
        if current_node in travelling_path:
            if travelling_path[:-1] not in self.main_list:
                self.main_list.append(travelling_path[:-1])
            return
        else:
            # print(travelling_path)
            travelling_path += (current_node,)
            for i in self.myserver.find_in_asset_vulnerability(current_node.node_id, current_node.access_level):
                asset_id_in, current_access_in = self.myserver.find_post_condition(i[1])
                # print(asset_id_in,current_access_in)
                new_node = self.node.create_asset_node(asset_id_in, current_access_in)

                vulnerability_id = i[1].split('.')[1]
                
                vulnerability_node = self.node.create_vulnerability_node(current_node, new_node, vulnerability_id)
                # self.set_distance_from_start(vulnerability_node, distance + 2)

                path = travelling_path + (vulnerability_node,)
                # print(new_node,goal_node,path)
                self.find_all_attackable_path(new_node,path)
            
            for j in self.myserver.find_out_of_asset_vulnerabilities(current_node.node_id, current_node.access_level):
                
                # reference what the data is in J
                # [['A1.high', 'A1.remote_access.A3', 'A3.CVE-2019-12749']]
                # kindly follow and update the upper data to get the 
                asset_id_out, current_access_out = self.myserver.find_post_condition(j[2])
                # print(asset_id_out,current_access_out)
                new_node = self.node.create_asset_node(asset_id_out, current_access_out)
                vulnerability_id = j[2].split('.')[1]
                connection_type = j[1].split('.')[1]
                vulnerability_node = self.node.create_vulnerability_node(current_node, new_node,
                                                            vulnerability_id=vulnerability_id,
                                                            connection_type=connection_type)
                # self.set_distance_from_start(vulnerability_node,distance + 2)
                path = travelling_path + (vulnerability_node,)
                self.find_all_attackable_path(new_node, path)

    def get_unique_nodes(self):
        self.unique_nodes = []
        for i in self.main_list:
            for j in i:
                if j not in self.unique_nodes:
                    self.unique_nodes.append(j)
    
    def list_to_adjacency_matrix(self):
        self.adjacency_dictionary = {}
        # self.unique_nodes = []
        # self.unique_nodes = self.node.asset_nodes + self.node.vulnerability_nodes
        # for i in self.unique_nodes:
        #     print(i)
        for i in self.unique_nodes:
            empty_list = []
            for j in range(len(self.main_list)):
                for k in range(len(self.main_list[j])-1):
                    if i == self.main_list[j][k]:
                        if self.main_list[j][k+1] not in empty_list:
                            empty_list.append(self.main_list[j][k+1])
            self.adjacency_dictionary[i] = empty_list


    def get_all_path(self,asset_id,current_access):
        empty_tuple = ()
        starting_node = self.node.create_asset_node(asset_id, current_access)
        # goal_node = self.node.create_asset_node(goal_asset_id, goal_access_level)
        # self.node.goal_asset_importance_score = goal_node.node_importance_score
        # 1. First its trying to find the path by using network
        # while finding path it also create nodes with value ** distance from start
        self.find_all_attackable_path(current_node=starting_node, travelling_path=empty_tuple)
        if len(self.main_list) == 0:

            # if no path is found then return 0 which will return an error page

            print(f'NO path FOUND for {starting_node} to {goal_node}')
            return 0

        print('PATHS FOUND ',len(self.main_list))
        # print(self.main_list)
        print('time taken ', self.number)

        # 2. creating adjacency matrix from 2D list
        self.get_unique_nodes()
        self.list_to_adjacency_matrix()

        # 3. calculate shortest distance to goal

        # self.calculate_shortest_path_to_target(goal_node=goal_node)

        # 4. now calculate the criticality score and impact score 
        # for i in self.node.vulnerability_nodes:
        #     i.calculate_criticality()

        three_most_connected_nodes = list(filter(lambda p: isinstance(p,Node),sorted(self.adjacency_dictionary,key=lambda x:len(self.adjacency_dictionary[x]),reverse=True)))
        print(three_most_connected_nodes)
        most_vulnerabilities = []
        for i in self.adjacency_dictionary:
            if any(item in three_most_connected_nodes for item in self.adjacency_dictionary[i]):
                most_vulnerabilities.append(i)

        most_vulnerabilities.sort(key= lambda x: x.vulnerabilty_score,reverse=True)
        print(most_vulnerabilities)
        # three_most_connected_nodes[0].color = '#FF0000'
        # three_most_connected_nodes[1].color = '#FF5733'
        # three_most_connected_nodes[2].color = '#FFA07A'
        
        most_vulnerabilities[0].color = '#FF0000'
        most_vulnerabilities[1].color = '#FF5733'
        try:
            most_vulnerabilities[2].color = '#FFA07A'
        except:
            pass
        # safe_nodes =[starting_node]
        # temp_nodes = list(self.adjacency_dictionary.keys()) # strong temp nodes
        # for i in temp_nodes:
        #     if len(self.adjacency_dictionary[i]) == 0 and i not in safe_nodes:
        #         self.adjacency_dictionary.pop(i)
        # 4. create JSON FROM THE DATA AND RETURN IT TO ROUTE.PY
        json_converter = Json_node_builder()
        return json_converter.list_to_node(self.adjacency_dictionary)


    
        
if __name__ == '__main__':
    # x = Find_ciritical_path()
    # try:
    #     print(x.get_critical_path('A1', 'low', 'A12', 'high'))
    # except:
    #     f.close()
    #     pass

    x1 = Find_attack_range()
    print(x1.get_all_path('A1','low'))
    # x = Find_critical_path_string_type()
    # x.get_critical_path('A1', 'low', 'A7', 'high')
# server connection files give access to server on my sql
from serverconnection import MyCursor_Operation
#edge builder uses the server to build edges
import edges_builder

# dataserver_connection = MyCursor_Operation()

# dummy dataset
nodes = ['c1','c2','c3','c4','c5','a1','a2','a3','a5','goal']
class GraphNode:

    def create_node_dict(self,start_node,goal_node):
        dataserver_connection = MyCursor_Operation()
        C = 0
        A = 0
        nodes_data = []
        # for i in nodes:
        #     if 'g' in i:
        #         nodes_data.append({ "data": { "id": f'{i}' ,"name":f'{i}'},"css":{'shape':'circle','background-color': "green"} })
        #         continue
        #     elif 'a' in i:
        #         nodes_data.append({ "data": { "id": f'{i}' ,"name":f'{i}'},"css":{'shape':'rectangle','background-color': "blue"} })
        #     else:
        #         nodes_data.append({ "data": { "id": f'{i}' ,"name":f'{i}'},"css":{'shape':'circle','background-color': "red"} })

        # for i in range(len(nodes)-1):
        #     nodes_data.append({'data': {'id': f'{i}','source': f'{nodes[i]}','target': f'{nodes[i+1]}','directed': 'true'}})
        # DUMMY TESTING ONLY 

        # edge builder passes two files. data dictionay which contains which nodes are connected to which
        # and next file as shorted path. which is just a tuple. and stored in session of user as COOKIE.
        data_dictionary,shortest_path = edges_builder.get_connection_edges(start_node,goal_node)
        nodes = [i for i in data_dictionary]
        for i in data_dictionary:
            if 'CVE' in i:
                cve_id, cwe_id, vulnerability_type , cve_score, access , complexity, description = [_ for _ in dataserver_connection.get_cve_information(i)]
                # node_data checks dictionary and create a another diciotnary form
                # Which then will be converted to json for Cytoscape to process

                nodes_data.append({ "data": { "id": f'{cve_id}',
                                                'node_id':f'C{C}',
                                                'name' : f'{cve_id}',
                                                'cwe_id':f'{cwe_id}',
                                                'vulnerability_type':f'{vulnerability_type}',
                                                'cve_score':f'{cve_score}',
                                                'access':f'{access}',
                                                'complexity':f'{complexity}',
                                                'description':f'{description}'},"css":{'shape':'circle'} })
                C += 1 # increasing ID number
            if 'attack' in i:
                attack_id, attack_name, description = [_ for _ in dataserver_connection.get_attack_information(i)]
                nodes_data.append({ "data": { "id": f'{attack_id}' ,
                                              "node_id":f'A{A}',
                                              'description':f'{description}',
                                              'name' : f'{attack_name}'},"css":{'shape':'rectangle','background-color': "blue"} })
                A+=1

        x = 0        
        for i in data_dictionary:
            for j in data_dictionary[i]:
                nodes_data.append({'data': {'id': f'X{x}',
                                   'source': f'{i}',
                                   'target': f'{j}',
                                   'directed': 'true',
                                   'description':f'Connecting {i} to --> {j}'}})
                x +=1
        
        return nodes_data,shortest_path # nodes data is a list of dictionaries (many dictionary) which then will be converted to JSON


    
    # to reduce the computation we store the shortest path in session cookie. then passes here to create node so that we can give faster response
    def create_node_from_list(self,path): # create nodes from a iterable object. [ c1 , a2 , c3 ] then the node builder will create c1 to a2 to c3 graph for cytoscaape
        dataserver_connection = MyCursor_Operation()
        nodes_data = []
        A,C = 0,0
        for i in path:
            if 'CVE' in i:
                cve_id, cwe_id, vulnerability_type , cve_score, access , complexity, description = [_ for _ in dataserver_connection.get_cve_information(i)] 
                # from the dataserver it get this values then passes with the nodes data. which then can be used for showing to user for further knowledge
                nodes_data.append({ "data": { "id": f'{cve_id}',
                                                'node_id':f'C{C}',
                                                'name' : f'{cve_id}',
                                                'cwe_id':f'{cwe_id}',
                                                'vulnerability_type':f'{vulnerability_type}',
                                                'cve_score':f'{cve_score}',
                                                'access':f'{access}',
                                                'complexity':f'{complexity}',
                                                'description':f'{description}'},"css":{'shape':'circle','background-color': "red"} })
                C += 1 # increasing ID number
            if 'attack' in i:
                attack_id, attack_name, description = [_ for _ in dataserver_connection.get_attack_information(i)]
                nodes_data.append({ "data": { "id": f'{attack_id}' ,
                                              "node_id":f'A{A}',
                                              'description':f'{description}',
                                              'name' : f'{attack_name}'},"css":{'shape':'rectangle','background-color': "blue"} })
                A+=1

        x = 0        
        for i in range(len(path)-1):
                nodes_data.append({'data': {'id': f'X{x}','source': f'{path[i]}','target': f'{path[i+1]}','directed': 'true','description':f'Connecting {path[i]} to --> {path[i+1]}'}})
                x +=1
        
        return nodes_data
    
    def nodebuilder(self,cve_id,goal_cve_id):
        nodes_data = []
        # data = database_server.get_description


# only for testing purpose to       
if __name__ == '__main__':
    x = GraphNode()
    print(x.create_node_dict(start_node='CVE-2022-20644', goal_node='CVE-2022-20788'))
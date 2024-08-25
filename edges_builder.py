import pandas as pd
from find_all_path import find_path_from_server

#get connection edges as dictionary
# created from the making_logic.ipynb file. there you can see the logic that was build aand here is the implementation so that py file can be
# used in the project
def get_connection_edges(start,goal):
    find_all_path = find_path_from_server()
    nodes_list, long_key_number , shortest_key_number , longest_path, shortest_path = find_all_path.get_paths(start,goal)
    path = [f'path_{i}' for i in range(len(longest_path))]  # generating path name for pandas dataframe
    df = pd.DataFrame(nodes_list,columns=path) # making a dataframe from the path
    dictionary = {}
    for i in range(len(path)-1):
        
        
        unique_value_for_path = df[path[i]].drop_duplicates().values.tolist()
        
        for j in unique_value_for_path:
            connections_from_current_path = df.loc[df[path[i]]==j,path[i+1]].drop_duplicates().values.tolist()
            
            if None in connections_from_current_path: # deleting node node
                for _ in range(connections_from_current_path.count(None)):
                    connections_from_current_path.remove(None)
            # print(j,connections_from_current_path)
            
            
            if j is not None: # none node is not there
                if j not in dictionary:
                    dictionary[j] = connections_from_current_path
                else:
                    dictionary[j] += connections_from_current_path

    for i in dictionary:
        dictionary[i] = list(set(dictionary[i]))
    
    return dictionary,shortest_path


# for testing purpose
if __name__ == '__main__':
    edges_connection_dictionary = get_connection_edges('CVE-2022-20644','CVE-2022-20788')
    for i in edges_connection_dictionary:
        print(f'{i} lenght = {len(edges_connection_dictionary[i])} = {edges_connection_dictionary[i]}')
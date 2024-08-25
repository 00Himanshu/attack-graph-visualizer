# this file mainly find all the paths and give output as list of tuples.
# doesn't matter how many it'll go through every path and will give output where it meets the goal

from serverconnection import MyCursor_Operation
# database_sever = MyCursor_Operation()
import pandas as pd

class find_path_from_server:
    def __init__(self):
        self.database_server = MyCursor_Operation()
        self.a = []

    def printpaths(self,path, current_node, goal):

        if current_node in path:
            # print(f'path failed = {path}')
            return
        # else:
        #     path.append(current_node)

        else:
            if goal == current_node:
                path = path + (current_node,)
                global a
                self.a.append(path)
                # print(f'SUCESS PATH = {path}')
                return

            elif 'CVE' in current_node:
                attack_ids = self.database_server.get_attacks(current_node)
                if len(attack_ids) == 0:
                    # print(f'CVE NOT FOUND {current_node} Path = {path}')
                    return
                path = path + (current_node,)
                for i in attack_ids:
                    self.printpaths(path, i, goal)

            elif 'attack' in current_node:
                cve_ids = self.database_server.get_posconditions(current_node)
                if len(cve_ids) == 0:
                    # print(f'Attack NOT FOUND {current_node} Path = {path}')
                    return
                path = path + (current_node,)
                for i in cve_ids:
                    self.printpaths(path, i, goal)

    def get_paths(self,start,goal):
        empty_list = ()
        # printpaths(empty_list, 'CVE-2022-20644', 'CVE-2022-20788')
        self.printpaths(empty_list, start, goal)


        dictionary = {}
        for i in range(len(self.a)):
            dictionary[i] = len(self.a[i])
        
        print(len(dictionary))

        long_key = max(dictionary, key=dictionary.get)
        short_key = min(dictionary, key=dictionary.get)
        # print(dictionary)
        print(f'Longest route = {self.a[long_key]}')
        print(f'shortest route = {self.a[short_key]}')
        return self.a,long_key,short_key,self.a[long_key],self.a[short_key]


if __name__ == '__main__':
    x = find_path_from_server()
    nodes_list, long_key_number , shortest_key_number , longest_path, shortest_path = x.get_paths('CVE-2022-20644','CVE-2022-20788')
    # print(nodes_list, long_key_number, shortest_key_number, longest_path, shortest_path)


# USES DFS to find the path. returns error if not found anything.
# access the data server to get attacks which are connected to cve_ids & cve_ids whcih are connected attacks

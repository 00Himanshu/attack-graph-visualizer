from distutils.command.build import build
from path_finding_v2 import Path_Finder
from serverconnection_v2 import MYSQL_connection


class Cytoscape_node_builder:
    def __init__(self):
        self.parent_count = 0
        self.path_finder = Path_Finder()
        self.parent_node_dict = {}

    def list_to_node(self, naming_directory, connection_directory):
        print(naming_directory, connection_directory)
        nodes = []
        for i in naming_directory:
            value = naming_directory[i]
            if type(value) == str:
                nodes.append({'data': {'id': f'{i}', 'name': f'{i}'}})
            else:
                nodes += self.compound_node(value)

        # creating connection now
        connections = 0
        for i in connection_directory:
            for j in connection_directory[i]:
                nodes.append({'data': {'id': f'X{connections}',
                                       'source': f'{i}',
                                       'target': f'{j}',
                                       'directed': 'true',
                                       'description':f'Connecting {i} to --> {j}'}})
                connections +=1
        return nodes

    def compound_node(self, list1d):
        x = []
        myserver = MYSQL_connection()
        asset_id , vulnerability = map(str,list1d[-1].split("."))
        parent_name = f'{list1d[0]}.{list1d[-1]}'
        for i in list1d:
            x.append({'data': {'id': f'{i}_{parent_name}',
                               'name': f'{i}', 'parent': f'{parent_name}'}})
        x.append({'data': {'id': f'{parent_name}',
                           'name': f'{list1d[0].split(".")[0]} to {list1d[-1].split(".")[0]} SCORE = {myserver.find_score(asset_id,vulnerability)}'}}, )
        self.parent_node_dict[parent_name] = self.parent_count
        self.parent_count += 1
        return x

    def build_node(self, asset_id, current_access):
        naming_directory, connection_directory = self.path_finder.get_path(asset_id=asset_id,
                                                                           current_access=current_access)
        return self.list_to_node(naming_directory, connection_directory)
    
    def build_brack_track_node(self,asset_id,current_access):
        naming_directory, connection_directory = self.path_finder.get_back_tracked_path(asset_id,current_access)
        return self.list_to_node(naming_directory,connection_directory)

    
if __name__ == '__main__':
    x = Cytoscape_node_builder()
    print(x.compound_node(['A1.high', 'A1.CVE-2019-1468']))
    print(x.compound_node(['A1.high', 'A1.remote_access.A3', 'A3.CVE-2019-12749']))
    # for i in x.build_node('A1', 'low'):
    #     print(i, end=',\n')
    # for i in x.build_brack_track_node('A14','high'):
    #     print(i,end=',\n')

import serverconnection_v2

class Back_Trackig:
    def __init__(self):
        self.mydb = serverconnection_v2()
        self.main_list = []

    def find_possible_attack(self,asset_id, current_access, travelled_path):
        # first check if current asset already in the main list
        if f'{asset_id}.{current_access}' in travelled_path:
            self.main_list.append(travelled_path)
            return


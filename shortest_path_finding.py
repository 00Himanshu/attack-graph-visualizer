# Python implementation to find the
# shortest path in the graph using
# dictionaries
# Function to find the shortest
# path between two nodes of a graph
from traceback import print_tb


def BFS_SP(graph, start, goal):
	explored = []
	
	# Queue for traversing the
	# graph in the BFS
	queue = [[start]]
	
	# If the desired node is
	# reached
	if start == goal:
		print("Same Node")
		return
	
	# Loop to traverse the graph
	# with the help of the queue
	while queue:
		path = queue.pop(0)
		node = path[-1]
		
		# Condition to check if the
		# current node is not visited
		if node not in explored:
			neighbours = graph[node]
			
			# Loop to iterate over the
			# neighbours of the node
			for neighbour in neighbours:
				new_path = list(path)
				new_path.append(neighbour)
				queue.append(new_path)
				
				# Condition to check if the
				# neighbour node is the goal
				if neighbour == goal:
					print("Shortest path = ", *new_path)
					return new_path
			explored.append(node)

	# Condition when the nodes
	# are not connected
	print("So sorry, but a connecting"\
				"path doesn't exist :(")
	return 0

# Driver Code
if __name__ == "__main__":


    graph = {'A1.low': ['A1.low.A1.CVE-2019-1468', 'A1.low.A3.CVE-2019-12749'], 'A1.low.A1.CVE-2019-1468': ['A1.high'], 'A1.high': ['A1.high.A3.CVE-2019-12749'], 'A1.high.A3.CVE-2019-12749': ['A3.high'], 'A3.high': ['A3.high.A7.CVE-2006-3486'], 'A3.high.A7.CVE-2006-3486': ['A7.high'], 'A7.high': [], 'A1.low.A3.CVE-2019-12749': ['A3.high']}
    x = BFS_SP(graph=graph,start='A1.low',goal='A7.high')
    for i in x:
        print(i,end= '------>')
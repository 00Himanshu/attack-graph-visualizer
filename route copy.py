from crypt import methods
import random
from flask import Flask, redirect,render_template, request, session, url_for
from nodebuilder import GraphNode
from serverconnection import MyCursor_Operation



# creating flask app to build a simple webframe work
app = Flask(__name__)
# sceret Key for storing session
app.secret_key = 'under_maintainance'


# redirecting from / to /home
@app.route('/')
def redirect_to_home():
    return redirect('/home')


# tesing home page. Only accessible if manually typed in the browser
@app.route('/testing_home')
def home_page():
    
    # data for storing the dictonary object. its same as node builder creates. you can watch to learn more.
    database_server = MyCursor_Operation()
    x = GraphNode()

    data = [{ "data": { "id": 'a',"name":'lol' } },
            { "data": { "id": 'b' ,"name":'LOL'},"css":{'shape':'rectangle','background-color': "blue"} },
            {'data': {'id': 'ab','source': 'a','target': 'b','directed': True}}]
    
    # render template render the html page with desired output
    # psses the data from python to html using JINJ syntex
    del x
    return render_template('index.html',nodes = data,layout='grid')


# testing page only available if manually typed
@app.route('/testing')
def testing_page():
    data = [{ "data": { "id": 'a',"name":'lol' ,'information':'E nana naka muka naka mukaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'} },
            { "data": { "id": 'b' ,"name":'LOL','information':'bhagggggggg'},"css":{'shape':'rectangle','background-color': "blue"} },
            { "data": { "id": 'precondition_a1_01','parent': 'a1' ,"name":'a1 Access','information':'bhagggggggg'},"css":{'shape':'rectangle','background-color': "blue"} },
            { "data": { "id": 'precondiction_a1_02','parent': 'a1' ,"name":'a1 - CVE - 2022- XXX','information':'bhagggggggg'},"css":{'shape':'rectangle','background-color': "blue"} },
            { "data": { "id": 'a1' ,"name":'LOL','information':'bhagggggggg'}} ,
            { "data": { "id": 'precondition_b1_01','parent': 'b1' ,"name":'a1 Access','information':'bhagggggggg'},"css":{'shape':'rectangle','background-color': "blue"} },
            { "data": { "id": 'precondiction_b1_02','parent': 'b1' ,"name":'a1 - CVE - 2022- XXX','information':'bhagggggggg'},"css":{'shape':'rectangle','background-color': "blue"} },
            { "data": { "id": 'b1' ,"name":'LOL','information':'bhagggggggg'}},
            { 'data': { 'id': 'ab','source': 'a','target': 'b','directed': 'true'}},
            { 'data': { 'id': 'a1-b','source': 'b','target': 'a1','directed': 'true'}},
            { 'data': { 'id': 'b1-b','source': 'b','target': 'b1','directed': 'true'}},
            ]
    data_new = [{'data': {'id': 'A1.low', 'name': 'A1.low'}},
                {'data': {'id': 'A1.low_A1.low.A1.CVE-2019-1468', 'name': 'A1.low', 'parent': 'A1.low.A1.CVE-2019-1468'}},
                {'data': {'id': 'A1.CVE-2019-1468_A1.low.A1.CVE-2019-1468', 'name': 'A1.CVE-2019-1468', 'parent': 'A1.low.A1.CVE-2019-1468'}},
                {'data': {'id': 'A1.low.A1.CVE-2019-1468', 'name': 'A1 to A1'}},
                {'data': {'id': 'A1.high', 'name': 'A1.high'}},
                {'data': {'id': 'A1.high_A1.high.A3.CVE-2019-12749', 'name': 'A1.high', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                {'data': {'id': 'A1.remote_access.A3_A1.high.A3.CVE-2019-12749', 'name': 'A1.remote_access.A3', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                {'data': {'id': 'A3.CVE-2019-12749_A1.high.A3.CVE-2019-12749', 'name': 'A3.CVE-2019-12749', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                {'data': {'id': 'A1.high.A3.CVE-2019-12749', 'name': 'A1 to A3'}},
                {'data': {'id': 'A3.high', 'name': 'A3.high'}},
                {'data': {'id': 'A3.high_A3.high.A7.CVE-2006-3486', 'name': 'A3.high', 'parent': 'A3.high.A7.CVE-2006-3486'}},
                {'data': {'id': 'A3.network_access.A7_A3.high.A7.CVE-2006-3486', 'name': 'A3.network_access.A7', 'parent': 'A3.high.A7.CVE-2006-3486'}},
                {'data': {'id': 'A7.CVE-2006-3486_A3.high.A7.CVE-2006-3486', 'name': 'A7.CVE-2006-3486', 'parent': 'A3.high.A7.CVE-2006-3486'}},
                {'data': {'id': 'A3.high.A7.CVE-2006-3486', 'name': 'A3 to A7'}},
                {'data': {'id': 'A7.high', 'name': 'A7.high'}},
                {'data': {'id': 'A1.low_A1.low.A3.CVE-2019-12749', 'name': 'A1.low', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                {'data': {'id': 'A1.remote_access.A3_A1.low.A3.CVE-2019-12749', 'name': 'A1.remote_access.A3', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                {'data': {'id': 'A3.CVE-2019-12749_A1.low.A3.CVE-2019-12749', 'name': 'A3.CVE-2019-12749', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                {'data': {'id': 'A1.low.A3.CVE-2019-12749', 'name': 'A1 to A3'}},
                {'data': {'id': 'X0', 'source': 'A1.low', 'target': 'A1.low.A1.CVE-2019-1468', 'directed': 'true', 'description': 'Connecting A1.low to --> A1.low.A1.CVE-2019-1468'}},
                {'data': {'id': 'X1', 'source': 'A1.low', 'target': 'A1.low.A3.CVE-2019-12749', 'directed': 'true', 'description': 'Connecting A1.low to --> A1.low.A3.CVE-2019-12749'}},
                {'data': {'id': 'X2', 'source': 'A1.low.A1.CVE-2019-1468', 'target': 'A1.high', 'directed': 'true', 'description': 'Connecting A1.low.A1.CVE-2019-1468 to --> A1.high'}},
                {'data': {'id': 'X3', 'source': 'A1.high', 'target': 'A1.high.A3.CVE-2019-12749', 'directed': 'true', 'description': 'Connecting A1.high to --> A1.high.A3.CVE-2019-12749'}},
                {'data': {'id': 'X4', 'source': 'A1.high.A3.CVE-2019-12749', 'target': 'A3.high', 'directed': 'true', 'description': 'Connecting A1.high.A3.CVE-2019-12749 to --> A3.high'}},
                {'data': {'id': 'X5', 'source': 'A3.high', 'target': 'A3.high.A7.CVE-2006-3486', 'directed': 'true', 'description': 'Connecting A3.high to --> A3.high.A7.CVE-2006-3486'}},
                {'data': {'id': 'X6', 'source': 'A3.high.A7.CVE-2006-3486', 'target': 'A7.high', 'directed': 'true', 'description': 'Connecting A3.high.A7.CVE-2006-3486 to --> A7.high'}},
                {'data': {'id': 'X7', 'source': 'A1.low.A3.CVE-2019-12749', 'target': 'A3.high', 'directed': 'true', 'description': 'Connecting A1.low.A3.CVE-2019-12749 to --> A3.high'}}]
    return render_template('testing.html',nodes = data_new,layout = 'cose-bilkent',root_node='a',page_name = 'Testing page')


# multinode is the page redirected from /home. it shows the node graph
@app.route('/multinode',methods = ['GET','POST'])
def multinode_exp():
    database_server = MyCursor_Operation()
    x = GraphNode()
    # precondition_test = [f'c{i}' for i in range(20)]
    # attack_test = [f'a{i}' for i in range(30)]
    # nodes = []
    # for i in range(50):
    #     nodes.append(random.choice(precondition_test))
    #     nodes.append(random.choice(attack_test))
    # nodes.append('goal')
    # print(x.create_node_dict(nodes))

    # gets the data from /home page and store it in python vairables
    selection_2 = request.form.get('option_2')
    selection_1 = request.form.get('option_1')

    # prints selected input into the terminal
    print(selection_1,selection_2)
    # storing in session for later use case. Changes when user selects again
    session['selection_1'] = selection_1
    session['selection_2'] = selection_2
    try:
        nodes_creations,shortest_path = x.create_node_dict(start_node=f'{selection_1}', goal_node=f'{selection_2}')
        del x
        # stored the stored path. in the session for faster operation in later on shortest path finding.
        session['shortest_path'] = shortest_path
        # session['nodes_creations'] = nodes_creations

        # layout enabled :
        # cola , cose-bilkent , spread
        # new layout added by importing the javascript

        return render_template('extended_testing.html',
                                nodes = nodes_creations,
                                layout = 'cola',
                                page_name = f'{selection_1} to {selection_2}',
                                root_node=str(selection_1),
                                button_name = 'Find Shortest Path',
                                redirection = 'shortest_path'
                                )

    except:
        return redirect('/route_not_found')

    
    # else:
    #     nodes_creations= session['nodes_creations']
    #     selection_1 , selection_2 = session['selection_1'],session['selection_2']
    #     return render_template('extended_testing.html',
    #                             nodes = nodes_creations,
    #                             layout = 'breadthfirst',
    #                             page_name = f'{selection_1} to {selection_2}',
    #                             root_node=str(selection_1),
    #                             button_name = 'Find Shortest path',
    #                             redirection = url_for('shortest_path_node')
    #                             )



@app.route('/home',methods=['GET'])
def home():
    x = GraphNode()
    database_server = MyCursor_Operation()
    for i in list(session.keys()):
        session.pop(i)
    precondition_labels = database_server.show_CVE()
    del x
    return render_template('home.html',preconditions = precondition_labels)

@app.route('/new_home',methods=['GET'])
def new_home():
    

@app.route('/shortest_path')
def shortest_path_node():
    x = GraphNode()
    print(session['shortest_path'])
    nodes_creations= x.create_node_from_list(session['shortest_path'])
    selection_1 , selection_2 = session['selection_1'],session['selection_2']
    # session.clear()
    del x
    return render_template('extended_testing.html',
                            nodes = nodes_creations,
                            layout = 'cola',
                            page_name = f'{selection_1} to {selection_2}',
                            root_node=str(selection_1),
                            button_name = 'Find all path',
                            redirection = 'javascript:history.back()'
                            )

# testing animation for the front page

@app.route('/test/animation')
def animation_tester():
    return render_template('node_animation.html')

# if any error then page redirects here
@app.route('/route_not_found')
def route_not_found():
    return render_template('error.html',
                           error_name = 'Route Not Found',
                           selection_1 = session['selection_1'],
                           selection_2 = session['selection_2'])



# starting the app on the local host 
if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True)
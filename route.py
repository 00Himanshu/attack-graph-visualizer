# from crypt import methods
import json
import random
from turtle import st
from flask import Flask, redirect,render_template, request, session, url_for
from nodebuilder import GraphNode
from serverconnection import MyCursor_Operation
import criticality_path_finder
# new vulnerability assesment 
from serverconnection_v2 import MYSQL_connection
from nodebuilder_v2 import Cytoscape_node_builder


'''
Currently there is 3 to 4 working page

/criticality_home

/testing

backTracking_home

new_home

home

'''

# creating flask app to build a simple webframe work
app = Flask(__name__)
# sceret Key for storing session
app.secret_key = 'under_maintainance'


# redirecting from / to /home
@app.route('/')
def redirect_to_home():
    return redirect('/criticality_home')


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
    data_now = [{'data': {'id': 'A1.low',
                    'name': 'A1.low',
                    'description': 'Node ID = A1Node_type = Windows 7Node Importance Score in the Network = 3Node distance from start = 9999',
                    'table_data': {'Asset Type': 'Windows 7', 'Access Level': 'low'}},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'A1.low.A1.high.CVE-2019-1468',
                    'name': 'CVE-2019-1468',
                    'description': 'From asset = A1 <br>TO asset = A1 <br>Node distance from start = 9999 <br>Node Distance to Goal = 0<br>Node vulnerability score = 3.9<br>Node Ciricality score = None<br>Node impact score = None',
                    'table_data': {'CVE ID': 'CVE-2019-1468',
                        'CVSS Score': 3.9,
                        'Mitre Attack ID': 'T1068',
                        'Mitre Defend ID': 'D3-EAL'}},
                    'css': {'shape': 'rectangle', 'background-color': '#87CEEB'}},
                    {'data': {'id': 'A1.high',
                    'name': 'A1.high',
                    'description': 'Node ID = A1Node_type = Windows 7Node Importance Score in the Network = 3Node distance from start = 9999',
                    'table_data': {'Asset Type': 'Windows 7', 'Access Level': 'high'}},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'A1.high.A3.high.CVE-2019-12749',
                    'name': 'CVE-2019-12749',
                    'description': 'From asset = A1 <br>TO asset = A3 <br>Node distance from start = 9999 <br>Node Distance to Goal = 0<br>Node vulnerability score = 4.7<br>Node Ciricality score = None<br>Node impact score = None',
                    'table_data': {'CVE ID': 'CVE-2019-12749',
                        'CVSS Score': 4.7,
                        'Mitre Attack ID': 'T1021',
                        'Mitre Defend ID': 'D3-MFA'}},
                    'css': {'shape': 'rectangle', 'background-color': '#FF5733'}},
                    {'data': {'id': 'A3.high',
                    'name': 'A3.high',
                    'description': 'Node ID = A3Node_type = Ubuntu 14Node Importance Score in the Network = 7Node distance from start = 9999',
                    'table_data': {'Asset Type': 'Ubuntu 14', 'Access Level': 'high'}},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'A3.high.A7.high.CVE-2006-3486',
                    'name': 'CVE-2006-3486',
                    'description': 'From asset = A3 <br>TO asset = A7 <br>Node distance from start = 9999 <br>Node Distance to Goal = 0<br>Node vulnerability score = 9.5<br>Node Ciricality score = None<br>Node impact score = None',
                    'table_data': {'CVE ID': 'CVE-2006-3486',
                        'CVSS Score': 9.5,
                        'Mitre Attack ID': 'T1203',
                        'Mitre Defend ID': 'D3-ITF'}},
                    'css': {'shape': 'rectangle', 'background-color': '#FF0000'}},
                    {'data': {'id': 'A7.high',
                    'name': 'A7.high',
                    'description': 'Node ID = A7Node_type = MySQL 5.3Node Importance Score in the Network = 9Node distance from start = 9999',
                    'table_data': {'Asset Type': 'MySQL 5.3', 'Access Level': 'high'}},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'A1.low.A3.high.CVE-2019-12749',
                    'name': 'CVE-2019-12749',
                    'description': 'From asset = A1 <br>TO asset = A3 <br>Node distance from start = 9999 <br>Node Distance to Goal = 0<br>Node vulnerability score = 4.7<br>Node Ciricality score = None<br>Node impact score = None',
                    'table_data': {'CVE ID': 'CVE-2019-12749',
                        'CVSS Score': 4.7,
                        'Mitre Attack ID': 'T1021',
                        'Mitre Defend ID': 'D3-MFA'}},
                    'css': {'shape': 'rectangle', 'background-color': '#FFA07A'}},
                    {'data': {'id': 'X0',
                    'source': 'A1.low',
                    'target': 'A1.low.A1.high.CVE-2019-1468',
                    'directed': 'true'}},
                    {'data': {'id': 'X1',
                    'source': 'A1.low',
                    'target': 'A1.low.A3.high.CVE-2019-12749',
                    'directed': 'true'}},
                    {'data': {'id': 'X2',
                    'source': 'A1.low.A1.high.CVE-2019-1468',
                    'target': 'A1.high',
                    'directed': 'true'}},
                    {'data': {'id': 'X3',
                    'source': 'A1.high',
                    'target': 'A1.high.A3.high.CVE-2019-12749',
                    'directed': 'true'}},
                    {'data': {'id': 'X4',
                    'source': 'A1.high.A3.high.CVE-2019-12749',
                    'target': 'A3.high',
                    'directed': 'true'}},
                    {'data': {'id': 'X5',
                    'source': 'A3.high',
                    'target': 'A3.high.A7.high.CVE-2006-3486',
                    'directed': 'true'}},
                    {'data': {'id': 'X6',
                    'source': 'A3.high.A7.high.CVE-2006-3486',
                    'target': 'A7.high',
                    'directed': 'true'}},
                    {'data': {'id': 'X7',
                    'source': 'A1.low.A3.high.CVE-2019-12749',
                    'target': 'A3.high',
                    'directed': 'true'}}]
    
    with open('tests/testing_1.json') as f:
        data_comp = json.load(f)
    
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
    
    custom_data = [{'data': {'id': 'I1', 'name': 'I1'},
                    'css': {'shape': 'rectangle', 'background-color': 'yellow'}},
                    {'data': {'id': 'I2', 'name': 'I2'},
                    'css': {'shape': 'rectangle', 'background-color': 'yellow'}},
                    {'data': {'id': 'I3', 'name': 'I3'},
                    'css': {'shape': 'rectangle', 'background-color': 'yellow'}},
                    {'data': {'id': 'I4', 'name': 'I4'},
                    'css': {'shape': 'rectangle', 'background-color': 'yellow'}},
                    {'data': {'id': '1', 'name': '1'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '2', 'name': '2'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '3', 'name': '3'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '4', 'name': '4'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '5', 'name': '5'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '6', 'name': '6'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '7', 'name': '7'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '8', 'name': '8'},
                    'css': {'shape': 'circle', 'background-color': 'red'}},
                    {'data': {'id': '9', 'name': '9'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '10', 'name': '10'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '11', 'name': '11'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '12', 'name': '12'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': '13', 'name': '13'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'G1', 'name': 'G1'},
                    'css': {'shape': 'circle', 'background-color': 'yellow'}},
                    {'data': {'id': 'G2', 'name': 'G2'},
                    'css': {'shape': 'circle', 'background-color': 'red'}},
                    {'data': {'id': 'G3', 'name': 'G3'},
                    'css': {'shape': 'circle', 'background-color': 'red'}},
                    {'data': {'id': 'X1', 'source': 'I1', 'target': '1', 'directed': 'true'}},
                    {'data': {'id': 'X2', 'source': 'I2', 'target': '7', 'directed': 'true'}},
                    {'data': {'id': 'X3', 'source': 'I3', 'target': '9', 'directed': 'true'}},
                    {'data': {'id': 'X4', 'source': 'I4', 'target': '11', 'directed': 'true'}},
                    {'data': {'id': 'X5', 'source': '1', 'target': '2', 'directed': 'true'}},
                    {'data': {'id': 'X6', 'source': '2', 'target': '3', 'directed': 'true'}},
                    {'data': {'id': 'X7', 'source': '2', 'target': '5', 'directed': 'true'}},
                    {'data': {'id': 'X8', 'source': '3', 'target': '4', 'directed': 'true'}},
                    {'data': {'id': 'X9', 'source': '4', 'target': 'G1', 'directed': 'true'}},
                    {'data': {'id': 'X10', 'source': '5', 'target': '6', 'directed': 'true'}},
                    {'data': {'id': 'X11', 'source': '6', 'target': '4', 'directed': 'true'}},
                    {'data': {'id': 'X12', 'source': '6', 'target': 'G2', 'directed': 'true'}},
                    {'data': {'id': 'X13', 'source': '7', 'target': '8', 'directed': 'true'}},
                    {'data': {'id': 'X14', 'source': '8', 'target': 'G2', 'directed': 'true'}},
                    {'data': {'id': 'X15', 'source': '8', 'target': 'G3', 'directed': 'true'}},
                    {'data': {'id': 'X16', 'source': '9', 'target': '5', 'directed': 'true'}},
                    {'data': {'id': 'X17', 'source': '9', 'target': '10', 'directed': 'true'}},
                    {'data': {'id': 'X18', 'source': '10', 'target': '12', 'directed': 'true'}},
                    {'data': {'id': 'X19', 'source': '11', 'target': '10', 'directed': 'true'}},
                    {'data': {'id': 'X20', 'source': '12', 'target': '8', 'directed': 'true'}},
                    {'data': {'id': 'X21', 'source': '12', 'target': '13', 'directed': 'true'}},
                    {'data': {'id': 'X22', 'source': '13', 'target': 'G3', 'directed': 'true'}}]
    
    custom_data_1 = [
        {'data': {'id': '2595089174815962507', 'name': 'USER(1.LINUX)'},
        'css': {'shape': 'circle', 'background-color': 'yellow'},'selected': True},
        {'data': {'id': '1775423458316358481', 'name': 'CVE-2015-1805'},
        'css': {'shape': 'rectangle', 'background-color': '#87CEEB'}},
        {'data': {'id': '458341061670945468', 'name': 'ROOT(1.LINUX)'},
        'css': {'shape': 'circle', 'background-color': 'yellow'}},
        {'data': {'id': '4143977315050589202', 'name': 'CVE-2008-0655'},
        'css': {'shape': 'rectangle', 'background-color': '#87CEEB'}},
        {'data': {'id': '5140889863994327969', 'name': 'USER(2.Adobe)'},
        'css': {'shape': 'circle', 'background-color': 'yellow'}},
        {'data': {'id': '-2686225106634555183', 'name': 'CVE-2014-4077','cve_id':'CVE-2014-4077','cwe_id':'843','cvss_data':'6.8','mitre_attack_id':'T1553','harden_data':'D3-DLIC','detect_data':'NO FOUND','color':'#87CEEB'},
        'css': {'shape': 'rectangle', 'background-color': '#87CEEB'}},
        {'data': {'id': '6422659981143440439', 'name': 'ROOT(3.WINDOWS)'},
        'css': {'shape': 'circle', 'background-color': 'yellow'}},
        {'data': {'id': '-2243033115120975770', 'name': 'CVE-2019-10980','cve_id':'CVE-2019-10980','cwe_id':'843','cvss_data':'6.8','mitre_attack_id':'T1203','harden_data':'D3-EHPV','detect_data':'D3-SSC','color':'#87CEEB'},
        'css': {'shape': 'rectangle', 'background-color': '#87CEEB'}},
        {'data': {'id': '-2411473928686658931', 'name': 'USER(3.LAquis SCADA)'},
        'css': {'shape': 'circle', 'background-color': 'yellow'}},
        {'data': {'id': '4370512633132320988', 'source': '2595089174815962507', 'target': '1775423458316358481', 'directed': 'true'}},
        {'data': {'id': '2233764519987303949', 'source': '1775423458316358481', 'target': '458341061670945468', 'directed': 'true'}},
        {'data': {'id': '4602318376721534670', 'source': '458341061670945468', 'target': '4143977315050589202', 'directed': 'true'}},
        {'data': {'id': '-2227884044963609715', 'source': '458341061670945468', 'target': '-2686225106634555183', 'directed': 'true'}},
        {'data': {'id': '9284867179044917171', 'source': '4143977315050589202', 'target': '5140889863994327969', 'directed': 'true'}},
        {'data': {'id': '2897856748873352199', 'source': '5140889863994327969', 'target': '-2243033115120975770', 'directed': 'true'}},
        {'data': {'id': '3736434874508885256', 'source': '-2686225106634555183', 'target': '6422659981143440439', 'directed': 'true'}},
        {'data': {'id': '4179626866022464669', 'source': '6422659981143440439', 'target': '-2243033115120975770', 'directed': 'true'}},
        {'data': {'id': '-4654507043807634701', 'source': '-2243033115120975770', 'target': '-2411473928686658931', 'directed': 'true'}}
        ]


    
    
    back_tracked_data = [{'data': {'id': 'A7.high', 'name': 'A7.high'}},
                        {'data': {'id': 'A7.Low_A7.Low.A7.CVE-2009-4030', 'name': 'A7.Low', 'parent': 'A7.Low.A7.CVE-2009-4030'}},
                        {'data': {'id': 'A7.CVE-2009-4030_A7.Low.A7.CVE-2009-4030', 'name': 'A7.CVE-2009-4030', 'parent': 'A7.Low.A7.CVE-2009-4030'}},
                        {'data': {'id': 'A7.Low.A7.CVE-2009-4030', 'name': 'A7 to A7'}},
                        {'data': {'id': 'A7.Low', 'name': 'A7.Low'}},
                        {'data': {'id': 'A2.high_A2.high.A7.CVE-2012-2749', 'name': 'A2.high', 'parent': 'A2.high.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A2.remote_access,A7_A2.high.A7.CVE-2012-2749', 'name': 'A2.remote_access,A7', 'parent': 'A2.high.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A7.CVE-2012-2749_A2.high.A7.CVE-2012-2749', 'name': 'A7.CVE-2012-2749', 'parent': 'A2.high.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A2.high.A7.CVE-2012-2749', 'name': 'A2 to A7'}},
                        {'data': {'id': 'A2.high', 'name': 'A2.high'}},
                        {'data': {'id': 'A2.low_A2.low.A7.CVE-2012-2749', 'name': 'A2.low', 'parent': 'A2.low.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A2.remote_access,A7_A2.low.A7.CVE-2012-2749', 'name': 'A2.remote_access,A7', 'parent': 'A2.low.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A7.CVE-2012-2749_A2.low.A7.CVE-2012-2749', 'name': 'A7.CVE-2012-2749', 'parent': 'A2.low.A7.CVE-2012-2749'}},
                        {'data': {'id': 'A2.low.A7.CVE-2012-2749', 'name': 'A2 to A7'}},
                        {'data': {'id': 'A2.low', 'name': 'A2.low'}},
                        {'data': {'id': 'A2.Low_A2.Low.A2.CVE-2017-11831', 'name': 'A2.Low', 'parent': 'A2.Low.A2.CVE-2017-11831'}},
                        {'data': {'id': 'A2.CVE-2017-11831_A2.Low.A2.CVE-2017-11831', 'name': 'A2.CVE-2017-11831', 'parent': 'A2.Low.A2.CVE-2017-11831'}},
                        {'data': {'id': 'A2.Low.A2.CVE-2017-11831', 'name': 'A2 to A2'}},
                        {'data': {'id': 'A2.Low', 'name': 'A2.Low'}},
                        {'data': {'id': 'A3.High_A3.High.A7.CVE-2006-3486', 'name': 'A3.High', 'parent': 'A3.High.A7.CVE-2006-3486'}},
                        {'data': {'id': 'A3.network_access,A7_A3.High.A7.CVE-2006-3486', 'name': 'A3.network_access,A7', 'parent': 'A3.High.A7.CVE-2006-3486'}},
                        {'data': {'id': 'A7.CVE-2006-3486_A3.High.A7.CVE-2006-3486', 'name': 'A7.CVE-2006-3486', 'parent': 'A3.High.A7.CVE-2006-3486'}},
                        {'data': {'id': 'A3.High.A7.CVE-2006-3486', 'name': 'A3 to A7'}},
                        {'data': {'id': 'A3.High', 'name': 'A3.High'}},
                        {'data': {'id': 'A1.high_A1.high.A3.CVE-2019-12749', 'name': 'A1.high', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A1.remote_access,A3_A1.high.A3.CVE-2019-12749', 'name': 'A1.remote_access,A3', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A3.CVE-2019-12749_A1.high.A3.CVE-2019-12749', 'name': 'A3.CVE-2019-12749', 'parent': 'A1.high.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A1.high.A3.CVE-2019-12749', 'name': 'A1 to A3'}},
                        {'data': {'id': 'A1.high', 'name': 'A1.high'}},
                        {'data': {'id': 'A1.Low_A1.Low.A1.CVE-2019-1468', 'name': 'A1.Low', 'parent': 'A1.Low.A1.CVE-2019-1468'}},
                        {'data': {'id': 'A1.CVE-2019-1468_A1.Low.A1.CVE-2019-1468', 'name': 'A1.CVE-2019-1468', 'parent': 'A1.Low.A1.CVE-2019-1468'}},
                        {'data': {'id': 'A1.Low.A1.CVE-2019-1468', 'name': 'A1 to A1'}},
                        {'data': {'id': 'A1.Low', 'name': 'A1.Low'}},
                        {'data': {'id': 'A1.High_A1.High.A1.CVE-2015-1727', 'name': 'A1.High', 'parent': 'A1.High.A1.CVE-2015-1727'}},
                        {'data': {'id': 'A1.CVE-2015-1727_A1.High.A1.CVE-2015-1727', 'name': 'A1.CVE-2015-1727', 'parent': 'A1.High.A1.CVE-2015-1727'}},
                        {'data': {'id': 'A1.High.A1.CVE-2015-1727', 'name': 'A1 to A1'}},
                        {'data': {'id': 'A1.High', 'name': 'A1.High'}},
                        {'data': {'id': 'A1.low_A1.low.A3.CVE-2019-12749', 'name': 'A1.low', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A1.remote_access,A3_A1.low.A3.CVE-2019-12749', 'name': 'A1.remote_access,A3', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A3.CVE-2019-12749_A1.low.A3.CVE-2019-12749', 'name': 'A3.CVE-2019-12749', 'parent': 'A1.low.A3.CVE-2019-12749'}},
                        {'data': {'id': 'A1.low.A3.CVE-2019-12749', 'name': 'A1 to A3'}},
                        {'data': {'id': 'A1.low', 'name': 'A1.low'}},
                        {'data': {'id': 'X0', 'source': 'A7.high', 'target': 'A7.Low.A7.CVE-2009-4030', 'directed': 'true', 'description': 'Connecting A7.high to --> A7.Low.A7.CVE-2009-4030'}},
                        {'data': {'id': 'X1', 'source': 'A7.high', 'target': 'A3.High.A7.CVE-2006-3486', 'directed': 'true', 'description': 'Connecting A7.high to --> A3.High.A7.CVE-2006-3486'}},
                        {'data': {'id': 'X2', 'source': 'A7.Low.A7.CVE-2009-4030', 'target': 'A7.Low', 'directed': 'true', 'description': 'Connecting A7.Low.A7.CVE-2009-4030 to --> A7.Low'}},
                        {'data': {'id': 'X3', 'source': 'A7.Low', 'target': 'A2.high.A7.CVE-2012-2749', 'directed': 'true', 'description': 'Connecting A7.Low to --> A2.high.A7.CVE-2012-2749'}},
                        {'data': {'id': 'X4', 'source': 'A7.Low', 'target': 'A2.low.A7.CVE-2012-2749', 'directed': 'true', 'description': 'Connecting A7.Low to --> A2.low.A7.CVE-2012-2749'}},
                        {'data': {'id': 'X5', 'source': 'A2.high.A7.CVE-2012-2749', 'target': 'A2.high', 'directed': 'true', 'description': 'Connecting A2.high.A7.CVE-2012-2749 to --> A2.high'}},
                        {'data': {'id': 'X6', 'source': 'A2.low.A7.CVE-2012-2749', 'target': 'A2.low', 'directed': 'true', 'description': 'Connecting A2.low.A7.CVE-2012-2749 to --> A2.low'}},
                        {'data': {'id': 'X7', 'source': 'A2.low', 'target': 'A2.Low.A2.CVE-2017-11831', 'directed': 'true', 'description': 'Connecting A2.low to --> A2.Low.A2.CVE-2017-11831'}},
                        {'data': {'id': 'X8', 'source': 'A2.Low.A2.CVE-2017-11831', 'target': 'A2.Low', 'directed': 'true', 'description': 'Connecting A2.Low.A2.CVE-2017-11831 to --> A2.Low'}},
                        {'data': {'id': 'X9', 'source': 'A3.High.A7.CVE-2006-3486', 'target': 'A3.High', 'directed': 'true', 'description': 'Connecting A3.High.A7.CVE-2006-3486 to --> A3.High'}},
                        {'data': {'id': 'X10', 'source': 'A3.High', 'target': 'A1.high.A3.CVE-2019-12749', 'directed': 'true', 'description': 'Connecting A3.High to --> A1.high.A3.CVE-2019-12749'}},
                        {'data': {'id': 'X11', 'source': 'A3.High', 'target': 'A1.low.A3.CVE-2019-12749', 'directed': 'true', 'description': 'Connecting A3.High to --> A1.low.A3.CVE-2019-12749'}},
                        {'data': {'id': 'X12', 'source': 'A1.high.A3.CVE-2019-12749', 'target': 'A1.high', 'directed': 'true', 'description': 'Connecting A1.high.A3.CVE-2019-12749 to --> A1.high'}},
                        {'data': {'id': 'X13', 'source': 'A1.high', 'target': 'A1.Low.A1.CVE-2019-1468', 'directed': 'true', 'description': 'Connecting A1.high to --> A1.Low.A1.CVE-2019-1468'}},
                        {'data': {'id': 'X14', 'source': 'A1.high', 'target': 'A1.High.A1.CVE-2015-1727', 'directed': 'true', 'description': 'Connecting A1.high to --> A1.High.A1.CVE-2015-1727'}},
                        {'data': {'id': 'X15', 'source': 'A1.Low.A1.CVE-2019-1468', 'target': 'A1.Low', 'directed': 'true', 'description': 'Connecting A1.Low.A1.CVE-2019-1468 to --> A1.Low'}},
                        {'data': {'id': 'X16', 'source': 'A1.High.A1.CVE-2015-1727', 'target': 'A1.High', 'directed': 'true', 'description': 'Connecting A1.High.A1.CVE-2015-1727 to --> A1.High'}},
                        {'data': {'id': 'X17', 'source': 'A1.High', 'target': 'A1.Low.A1.CVE-2019-1468', 'directed': 'true', 'description': 'Connecting A1.High to --> A1.Low.A1.CVE-2019-1468'}},
                        {'data': {'id': 'X18', 'source': 'A1.low.A3.CVE-2019-12749', 'target': 'A1.low', 'directed': 'true', 'description': 'Connecting A1.low.A3.CVE-2019-12749 to --> A1.low'}}]
    nodes_creations = [{'data': {'id': 'A1.low', 'name': 'A1.low', 'description': 'Node ID = A1Node_type = Windows 7Node Importance Score in the Network = 3Node distance from start = 1'}}, {'data': {'id': 'A7.high', 'name': 'A7.high', 'description': 'Node ID = A7Node_type = MySQL 5.3Node Importance Score in the Network = 9Node distance from start = 5'}}, {'data': {'id': 'A1.high', 'name': 'A1.high', 'description': 'Node ID = A1Node_type = Windows 7Node Importance Score in the Network = 3Node distance from start = 3'}}, {'data': {'id': 'A3.high', 'name': 'A3.high', 'description': 'Node ID = A3Node_type = Ubuntu 14Node Importance Score in the Network = 7Node distance from start = 3'}}, {'data': {'id': 'A1.low.A1.high.CVE-2019-1468', 'name': 'A1.low.A1.high.CVE-2019-1468', 'description': 'From asset = A1 <br>TO asset = A1 <br>Node distance from start = 2 <br>Node Distance to Goal = 6<br>Node vulnerability score = 3.9<br>Node Ciricality score = 0.65<br>Node impact score = 0.325'}}, {'data': {'id': 'A1.high.A1.high.CVE-2019-1468', 'name': 'A1.high.A1.high.CVE-2019-1468', 'description': 'From asset = A1 <br>TO asset = A1 <br>Node distance from start = 4 <br>Node Distance to Goal = 0<br>Node vulnerability score = 3.9<br>Node Ciricality score = None<br>Node impact score = None'}}, {'data': {'id': 'A1.high.A1.high.CVE-2015-1727', 'name': 'A1.high.A1.high.CVE-2015-1727', 'description': 'From asset = A1 <br>TO asset = A1 <br>Node distance from start = 4 <br>Node Distance to Goal = 0<br>Node vulnerability score = 3.3<br>Node Ciricality score = None<br>Node impact score = None'}}, {'data': {'id': 'A1.high.A3.high.CVE-2019-12749', 'name': 'A1.high.A3.high.CVE-2019-12749', 'description': 'From asset = A1 <br>TO asset = A3 <br>Node distance from start = 4 <br>Node Distance to Goal = 4<br>Node vulnerability score = 4.7<br>Node Ciricality score = 1.175<br>Node impact score = 0.29375'}}, {'data': {'id': 'A3.high.A7.high.CVE-2006-3486', 'name': 'A3.high.A7.high.CVE-2006-3486', 'description': 'From asset = A3 <br>TO asset = A7 <br>Node distance from start = 4 <br>Node Distance to Goal = 2<br>Node vulnerability score = 9.5<br>Node Ciricality score = 4.75<br>Node impact score = 1.1875'}}, {'data': {'id': 'A1.low.A3.high.CVE-2019-12749', 'name': 'A1.low.A3.high.CVE-2019-12749', 'description': 'From asset = A1 <br>TO asset = A3 <br>Node distance from start = 2 <br>Node Distance to Goal = 4<br>Node vulnerability score = 4.7<br>Node Ciricality score = 1.175<br>Node impact score = 0.5875'}}, {'data': {'id': 'X0', 'source': 'A1.low', 'target': 'A1.low.A1.high.CVE-2019-1468', 'directed': 'true'}}, {'data': {'id': 'X1', 'source': 'A1.low', 'target': 'A1.low.A3.high.CVE-2019-12749', 'directed': 'true'}}, {'data': {'id': 'X2', 'source': 'A1.high', 'target': 'A1.high.A3.high.CVE-2019-12749', 'directed': 'true'}}, {'data': {'id': 'X3', 'source': 'A3.high', 'target': 'A3.high.A7.high.CVE-2006-3486', 'directed': 'true'}}, {'data': {'id': 'X4', 'source': 'A1.low.A1.high.CVE-2019-1468', 'target': 'A1.high', 'directed': 'true'}}, {'data': {'id': 'X5', 'source': 'A1.high.A3.high.CVE-2019-12749', 'target': 'A3.high', 'directed': 'true'}}, {'data': {'id': 'X6', 'source': 'A3.high.A7.high.CVE-2006-3486', 'target': 'A7.high', 'directed': 'true'}}, {'data': {'id': 'X7', 'source': 'A1.low.A3.high.CVE-2019-12749', 'target': 'A3.high', 'directed': 'true'}}]
    
    # return render_template('UPDATED DATA SHOW.html',nodes = custom_data_1,layout = 'breadthfirst',root_node='#2595089174815962507',page_name = 'Testing page')
    return render_template('dyamic data update page testing.html',nodes = data_comp,layout = 'breadthfirst',root_node='#A1.low',page_name = 'Testing page')



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
    database_server = MYSQL_connection()
    assets = database_server.show_assets()
    return render_template('new_home_page_v2.html',link = url_for('new_multinode'),assets = assets,levels = ['High' , 'Low'])

@app.route('/backTracking_home',methods=['GET'])
def backtracking_home():
    database_server = MYSQL_connection()
    assets = database_server.show_assets()
    return render_template('new_home_page_v2.html',link = url_for('back_tracking_visualizer'),assets = assets,levels = ['High' , 'Low'])

@app.route('/new_multinode',methods = ['GET','POST'])
def new_multinode():
    selection_2 = request.form.get('option_2')
    selection_1 = request.form.get('option_1')
    print(selection_1,selection_2)
    selection_1 = selection_1.split('-')[0].replace(" ","")
    selection_2 = selection_2.lower()

    # nodebuilder = Cytoscape_node_builder()
    # data_new = nodebuilder.build_node(asset_id= selection_1,current_access=selection_2)
    # # return str(nodebuilder.build_node(asset_id= selection_1,current_access=selection_2))
    
    # return render_template('testing.html',nodes = data_new,layout = 'cose-bilkent',root_node='a',page_name = 'Multinode Version 2')
    x = criticality_path_finder.Find_attack_range()

    nodes_creations = x.get_all_path(asset_id=selection_1, current_access=selection_2)
    print(nodes_creations)
    #   dyamic data update page testing.html
    return render_template('dyamic data update page testing.html',nodes = nodes_creations,layout = 'breadthfirst',root_node=f'#{selection_1}.{selection_2}',page_name = f'{selection_1} to ALL PATH')
    
@app.route('/back_tracking_visualizer',methods = ['GET','POST'])
def back_tracking_visualizer():
    selection_2 = request.form.get('option_2')
    selection_1 = request.form.get('option_1')
    print(selection_1,selection_2)
    selection_1 = selection_1.split('-')[0].split()
    selection_2 = selection_2.lower()


    nodebuilder = Cytoscape_node_builder()
    data_new = nodebuilder.build_brack_track_node(asset_id= selection_1,current_access=selection_2)
    # return str(nodebuilder.build_node(asset_id= selection_1,current_access=selection_2))
    
    return render_template('testing.html',nodes = data_new,layout = 'cose-bilkent',root_node='#a',page_name = 'Multinode Version 2')

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
                            root_node=f"#{str(selection_1)}",
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


#####################################################################


@app.route('/criticality_home')
def criticality_home():
    database_server = MYSQL_connection()
    assets = database_server.show_criticality_assets()
    return render_template('critcality_home.html',link = url_for('criticality_multinode_visualizer'),assets = assets,levels = ['High' , 'Low'])

@app.route('/criticality_multinode_visualizer',methods = ['GET',"POST"])
def criticality_multinode_visualizer():
    start_node = request.form.get('start_option_1').replace("'",'"')
    start_node = json.loads(start_node)['asset']
    
    start_access_level = request.form.get('start_option_2').lower()
    
    end_node = request.form.get('end_option_1').replace("'",'"')
    end_node = json.loads(end_node)['asset']
    end_access_level = request.form.get('end_option_2').lower()


    x = criticality_path_finder.Find_ciritical_path()
    print(start_node,start_access_level,end_node,end_access_level)
    nodes_creations = x.get_critical_path(start_node,start_access_level,end_node,end_access_level)
    #   dyamic data update page testing.html
    print(nodes_creations)
    return render_template('dyamic data update page testing.html',nodes = nodes_creations,layout = 'breadthfirst',root_node=f'#{start_node}.{start_access_level}',page_name = f'{start_node} to {end_node}')
    
    
    
    # return render_template('testing.html',nodes = nodes_creations,layout = 'breadthfirst',root_node=f'#{start_node}.{start_access_level}',page_name = 'Testing page')
    # return redirect('/criticality_home')  # returning to home change this when the coding is finished


# starting the app on the local host 
if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True,port=5001)
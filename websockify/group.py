#!/usr/bin/env python
import subprocess

gpolicy = { }
    
def group(users, hosts, ousers, ohosts):
    '''The func handle group policy for one group. Users can access hosts.'''
    pass
def get_users_hosts(gpolicy):
    '''The func Get the all user list, hosts, hosts_access'''
    users = set()
    hosts = {}
    hosts_access = {}
    # Get the all user list, hosts, hosts_access
    for group in gpolicy['Groups']:
        if not group.has_key('Name'):
            print "The group do not have key [Name]"
            continue;
        for user in group['Users']:
            users.add(user)
            if not hosts_access.has_key(user):
                hosts_access[user] = set()
            if group.has_key('Hosts'):
                hosts_access[user] = hosts_access[user].union(group['Hosts'])
        # get all host list.
        if group.has_key('Hosts'):
            for host in group['Hosts']:
                hosts[host] = ''
    return users, hosts, hosts_access
def get_super_users(gpolicy, users, hosts_access):
    '''The func Get all super user list. User in super user list need be 
    deleted in user list and hosts_access.'''
    super_users = set()
    # Get all super user list.
    for group in gpolicy['Groups']:
        if not group.has_key('Name'):
            print "The group do not have key [Name]"
            continue;
        if not group.has_key('Hosts'):
            for user in group['Users']:
                # Delete super user from normal user list.
                if user in users:
                    users.remove(user)
                    del hosts_access[user]
                super_users.add(user)
    return (super_users, users, hosts_access)
def get_unaccess_hosts(hosts_access, hosts):
    hosts_unaccess = {}
    for user in hosts_access.keys():
        hosts_unaccess[user] = set()
        for host in hosts:
            if host not in hosts_access[user]:
                hosts_unaccess[user].add(host)
    return hosts_unaccess
def can_access(username, node_url, gpolicy):
    '''The func return true or False, based on gpolicy allowing username to node_url or not.'''
    if not gpolicy.has_key('ExperimentDomainName'):
        print 'Err: no ExperimentDomainName'
        return True
    ename = gpolicy['ExperimentDomainName']
    exp_name = ename
    dnode = node_url[:node_url.find('.')]
    dexp = node_url[node_url.find('.')+1:]
    if dexp != exp_name :
        # not the experience group return true.
        return True
    for group in gpolicy['Groups']:
        find_host = False
        find_user = False
        if not group.has_key('Name'):
            print "The group do not have key [Name]"
            continue;
        if group.has_key('Hosts'):
            for host in group['Hosts']:
                if host == dnode:
                    find_host = True
        else:
            #super user group, can access all nodes.
            find_host = True
        if group.has_key('Users'):
            for user in group['Users']:
                if username == user:
                    find_user = True
        if find_host and find_user :
            return True
    return False
    
def group_exp(gpolicy):
    ename = gpolicy['ExperimentDomainName']
    users = ()
    super_users = ()
    hosts = {}
    hosts_access = {}
    hosts_unaccess = {}
    # Get the all user list, hosts, hosts_access
    (users, hosts, hosts_access) = get_users_hosts(gpolicy)
    # Get all super user list.
    (super_users, users, hosts_access) = get_super_users(gpolicy, users, hosts_access)
    # produce unaccess hosts for every user.
    hosts_unaccess = get_unaccess_hosts(hosts_access, hosts)
                
    # For every normal user, get all accessable host list and give access right, other give no right.
    for user in users:
        for host in hosts_access[user]:
            hosts[host] += 'sudo usermod -e "" %s\n' % user
    for user in users:
        for host in hosts_unaccess[user]:
            hosts[host] += 'sudo usermod -e 1 %s\n' % user
    # For every super user, give all access.
    for user in super_users:
        for host in hosts.keys():
            hosts[host] += 'sudo usermod -e "" %s\n' % user
    return hosts
def test():
    gpolicy = {
        "ExperimentDomainName":"EnterpriseNetwork.NYPSOC.ncl.sg",
        'Groups':[]
    }
    assert get_users_hosts(gpolicy) == (set([]), {}, {})
    
    gpolicy = {
        "ExperimentDomainName":"EnterpriseNetwork.NYPSOC.ncl.sg",
        'Groups':[{
            'Name':'Red',
            'Users': ["user1", "user2"],
            'Hosts': ["n1"]
        },
        {
            'Name':'Blue',
            'Users': ['user3'],
            'Hosts': ['n2','n3']
        },
        {
            'Name':'Grey',
            'Users': ['user4'],
            'Hosts': []
        },
        {
            'Name':'Super',
            'Users': ['user3']
        }]
    }
    (users, hosts, hosts_access) = get_users_hosts(gpolicy)
    assert (users, hosts, hosts_access) == (set(['user4', 'user2', 'user3', 'user1']),\
        {'n1': '', 'n2': '', 'n3': ''}, \
        {'user4': set([]), 'user2': set(['n1']), 'user3': set(['n2', 'n3']), 'user1': set(['n1'])})
    assert get_unaccess_hosts(hosts_access, hosts) == {
        'user4': set(['n1', 'n2', 'n3']), 'user2': set(['n2', 'n3']), 
        'user3': set(['n1']), 'user1': set(['n2', 'n3'])}
    (super_users, users, hosts_access) = get_super_users(gpolicy, users, hosts_access)
    assert (super_users, users, hosts_access) == (set(['user3']), 
        set(['user4', 'user2', 'user1']), \
        {'user4': set([]), 'user2': set(['n1']), 'user1': set(['n1'])})
    assert get_unaccess_hosts(hosts_access, hosts) == {
        'user4': set(['n1', 'n2', 'n3']), 'user2': set(['n2', 'n3']),
        'user1': set(['n2', 'n3'])}
    print group_exp(gpolicy)
    group_exp(gpolicy) == {'n1': 'sudo usermod -e "" user2\nsudo usermod -e "" user1\nsudo usermod -e 1 user4\nsudo usermod -e "" user3\n', 'n2': 'sudo usermod -e 1 user4\nsudo usermod -e 1 user2\nsudo usermod -e 1 user1\nsudo usermod -e "" user3\n', 'n3': 'sudo usermod -e 1 user4\nsudo usermod -e 1 user2\nsudo usermod -e 1 user1\nsudo usermod -e "" user3\n'}
        
    assert get_unaccess_hosts({'user1': set(['n1'])}, {'n1': ''}) == {'user1': set([])}
    assert get_unaccess_hosts({'user1': set([])}, {'n1': ''}) == {'user1': set(['n1'])}
    assert get_unaccess_hosts({'user1': set(['n1', 'n2'])}, {'n1': '', 'n2': ''}) == {'user1': set([])}
    
    gpolicy = {
        "ExperimentDomainName":"EnterpriseNetwork.NYPSOC.ncl.sg",
        'Groups':[{
            'Name':'Red',
            'Users': ["user1", "user2"],
            'Hosts': ["n1"]
        },
        {
            'Name':'Blue',
            'Users': ['user1'],
            'Hosts': ['n2','n3']
        }        ]
    }
    (users, hosts, hosts_access) = get_users_hosts(gpolicy)
    #print (users, hosts, hosts_access)
    assert (users, hosts, hosts_access) == (set(['user2', 'user1']), \
        {'n1': '', 'n2': '', 'n3': ''}, {'user2': set(['n1']), 'user1': set(['n1', 'n2', 'n3'])})
    gpolicy = {
        "ExperimentDomainName":"EnterpriseNetwork.NYPSOC.ncl.sg",
        'Groups':[{
            'Name':'Red',
            'Users': ["user1", "user2"],
            'Hosts': ["n1"]
        },
        {
            'Name':'Blue',
            'Users': ['user1'],
            'Hosts': ['n2','n3']
        }, 
        { 'Name':'superusers', 'Users':['suser']}
        ]
    }
    assert can_access('user1', 'n1.EnterpriseNetwork.NYPSOC.ncl.sg', gpolicy) == True
    assert can_access('user1', 'n1.another.NYPSOC.ncl.sg', gpolicy) == True
    assert can_access('user1', 'n2.EnterpriseNetwork.NYPSOC.ncl.sg', gpolicy) == True
    assert can_access('user2', 'n2.EnterpriseNetwork.NYPSOC.ncl.sg', gpolicy) == False
    assert can_access('user3', 'n2.EnterpriseNetwork.NYPSOC.ncl.sg', gpolicy) == False
    assert can_access('suser', 'n2.EnterpriseNetwork.NYPSOC.ncl.sg', gpolicy) == True
    

def main():
    '''The func is the main func.'''
    import sys
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test()
        print "Pass all test"
        exit()
    if (len(sys.argv) == 2) and (sys.argv[1] == "do"):
        gp1 = { }		
        node_cmd_list = group_exp(gp1)
        ename = gp1['ExperimentDomainName']

        for (node, cmd) in node_cmd_list.items():
            cmdline = "echo '%s' | ssh %s.%s" % (cmd, node, ename)
            subprocess.call(cmdline, shell = True)

if __name__ == "__main__":
    main()

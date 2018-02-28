#!/usr/bin/env python
'''The program encode and decode the string with base64 and hash to validate the integrality.
'''
import sys
import hashlib
import base64
# Please change the salt for your own project.
SALT = "Some salt for security. liqun@ncl.sg"
def encode(str):
    ''' The func encode str, hash it and base64 it.'''
    alg = hashlib.sha256()
    alg.update(str)
    alg.update(SALT)
    hash = alg.hexdigest()
    return base64.urlsafe_b64encode(hash+':'+str)
def decode(str):
    ''' The func decode str, validate with hash and base64.decode it.'''
    str1 = base64.urlsafe_b64decode(str)
    pos = str1.find(':')
    if pos == -1: 
        return ''
    hash = str1[0:pos]
    alg = hashlib.sha256()
    alg.update(str1[pos+1:])
    alg.update(SALT)
    hash1 = alg.hexdigest()
    if hash != hash1:
        print "Error: str hash different"
        return ''
    return str1[pos+1:]
def get_server_from_path(path, is_encoded):
    '''The func decode host port from path parameter.
    path looks like [/encode(n1.soc.cloud.ncl.sg:5901)] 
    '''
    try:
        if is_encoded:
            str = decode(path[1:])
        else:
            str = path[1:]
        if str == '':
            return '', 0
        phost = ''
        phost = str.split(':')[0]
        pport = int(str.split(':')[1])
    except:
        return phost, 0
    return phost, pport

def test_basic():
    '''The func test some basic func.'''
    assert get_server_from_path('/n1.soc.cloud.ncl.sg:5901', False) == ('n1.soc.cloud.ncl.sg', 5901)
    
    str = "n1.soc.cloud.ncl.sg:5901"
    enc = encode(str)
    dec = decode(enc)
    assert str == dec
    assert get_server_from_path('/'+enc, True) == ('n1.soc.cloud.ncl.sg', 5901)
def main():
    '''The func is the main func.'''
    import sys
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test_basic()
        print "Pass all test"
        exit()
    elif (len(sys.argv) == 2):
        print encode(sys.argv[1])
    elif (len(sys.argv) == 3) and (sys.argv[1] == "decode"):
        print decode(sys.argv[2])
    elif (len(sys.argv) == 3) and (sys.argv[1] == "debase"):
        str1 = base64.urlsafe_b64decode(sys.argv[2])
        print str1
    else:
        print '''%s [content to encode]
        decode [content to decode]
        test''' % sys.argv[0]
        
if __name__ == "__main__":
    main()


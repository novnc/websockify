#!/usr/bin/env python
'''The program encode and decode the string with base64 and hash to validate the integrality.
'''
import sys
import hashlib
import base64
import datetime
# Please change the salt for your own project.
SALT = "Some salt for security. liqun@ncl.sg"
def qencode(str, create_date=datetime.date.today(), salt=SALT):
    ''' The func encode str, hash it and base64 it.'''
    alg = hashlib.sha256()
    tstr = create_date.strftime("%Y%m%d")
    alg.update(tstr)
    alg.update(':')
    alg.update(str)
    alg.update(salt)
    hash = alg.hexdigest()
    return base64.urlsafe_b64encode(hash+tstr+':'+str)
def qdecode(str, valid_daynum=3, salt=SALT):
    ''' The func decode str, validate with hash and base64.decode it. 
    If valid_daynum =0, only today is valid.'''
    str1 = base64.urlsafe_b64decode(str)
    pos = str1.find(':')
    if pos == -1: 
        return ''
    hash = str1[0:pos-8]
    tstr = str1[pos-8:pos]
    url_date = datetime.date(int(str1[pos-8:pos-4]), int(str1[pos-4:pos-2]), int(str1[pos-2:pos]))
    today = datetime.date.today()
    if (today - url_date) > datetime.timedelta(valid_daynum):
        return ''
    alg = hashlib.sha256()
    alg.update(str1[pos-8:])
    alg.update(salt)
    hash1 = alg.hexdigest()
    if hash != hash1:
        return ''
    return str1[pos+1:]
def get_server_from_path(path, is_encoded, valid_daynum=3, salt=SALT):
    '''The func decode host port from path parameter.
    path looks like [/qencode(n1.soc.cloud.ncl.sg:5901)] 
    '''
    try:
        if is_encoded:
            str = qdecode(path[1:], valid_daynum, salt)
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
    enc = qencode(str)
    print enc
    print base64.urlsafe_b64decode(enc)
    dec = qdecode(enc)
    assert str == dec
    assert get_server_from_path('/'+enc, True) == ('n1.soc.cloud.ncl.sg', 5901)
    enc = qencode(str, datetime.date(2018, 2, 24))
    assert (get_server_from_path('/'+enc, True)) == ('', 0)
    enc = qencode(str, datetime.date.today(), 'test salt')
    dec = qdecode(enc, 3, 'test salt')
    assert str == dec
    dec = qdecode(enc, 3, 'test salt1')
    assert dec == ''
def main():
    '''The func is the main func.'''
    import sys
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test_basic()
        print "Pass all test"
        exit()
    elif (len(sys.argv) == 2):
        print qencode(sys.argv[1])
    elif (len(sys.argv) == 3) and (sys.argv[1] == "decode"):
        print qdecode(sys.argv[2])
    elif (len(sys.argv) == 5) and (sys.argv[1] == "decode"):
        print qdecode(sys.argv[2],sys.argv[3],sys.argv[4])
    elif (len(sys.argv) == 5) and (sys.argv[1] == "encode"):
        print qencode(sys.argv[2],sys.argv[3],sys.argv[4])
    elif (len(sys.argv) == 3) and (sys.argv[1] == "debase"):
        str1 = base64.urlsafe_b64decode(sys.argv[2])
        print str1
    else:
        print '''%s [content to encode] [valid day number:3] [salt to encrypt]
        decode [content to decode] [valid day number:3] [salt to encrypt]
        test''' % sys.argv[0]
        
if __name__ == "__main__":
    main()

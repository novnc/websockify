# -*- mode: python -*-
# To be used with https://www.pyinstaller.org to build a "frozen" executable distribution
# Tested with pyinstaller 3.4, python 3.7.2, linux x86_64
# NOT tested with SSL

# Set to True to bring in numpy if available (increases output package size by ~45MB on linux64/python3.7).
# If False it will be left out
USE_NUMPY=True

# Get debug messages by pyinstaller bootloader
DEBUG=False

# Explicitly excluded modules
excludes = []

# It is possible to reduce the resulting package size (~3MB on linux64/python3.7)
# by excluding unused encodings.
# By default (as of pyinstaller 3.4/python 3.7) all encodings are pulled in:
# the following list can be used to reduce the encodings pulled in to the bare minimum.
# You should include the target platform encoding or call locale.setlocale(locale.LC_ALL, 'C')
# early in websockify_init()
#
# These are required:
#  - 'encodings.base64_codec' This is required when payload is b64 encoded, don't exclude
#  - 'encodings' Father package must also be included
#  - 'encodings.aliases' Required, see initstdio() function in cPython sources
#  - 'encodings.utf_8'
#  - 'encodings.latin_1'
#  - 'encodings.ascii' Required by some cascaded import from http
#  -  encodings.idna' Required by <I don't know>
# excludes.extend(('encodings.undefined', 'encodings.utf_32_be', 'encodings.utf_32',
#     'encodings.utf_16_le', 'encodings.utf_16_be', 'encodings.utf_16', 'encodings.utf_32_le',
#     'encodings.zlib_codec', 'encodings.euc_jis_2004', 'encodings.ptcp154', 'encodings.cp874',
#     'encodings.cp424',
#     'encodings.iso2022_jp_2', 'encodings.euc_jp', 'encodings.mac_arabic', 'encodings.shift_jis',
#     'encodings.utf_7', 'encodings.cp866', 'encodings.cp855', 'encodings.rot_13', 'encodings.cp1006',
#     'encodings.johab', 'encodings.cp865', 'encodings.mac_cyrillic', 'encodings.cp737', 'encodings.kz1048',
#     'encodings.cp1256', 'encodings.cp1252', 'encodings.hp_roman8', 'encodings.cp1026', 'encodings.iso8859_6',
#     'encodings.hz', 'encodings.shift_jisx0213', 'encodings.cp500', 'encodings.palmos', 'encodings.euc_jisx0213',
#     'encodings.cp864', 'encodings.cp875', 'encodings.mac_iceland', 'encodings.cp856', 'encodings.big5',
#     'encodings.iso2022_jp_ext', 'encodings.charmap', 'encodings.iso8859_7', 'encodings.cp852',
#     'encodings.mac_croatian', 'encodings.bz2_codec', 'encodings.cp863', 'encodings.iso8859_14',
#     'encodings.cp65001', 'encodings.cp1254', 'encodings.iso2022_jp_2004', 'encodings.cp932',
#     'encodings.raw_unicode_escape', 'encodings.mac_romanian', 'encodings.gb18030', 'encodings.cp1257',
#     'encodings.mac_latin2', 'encodings.iso2022_kr', 'encodings.shift_jis_2004', 'encodings.cp850',
#     'encodings.iso2022_jp_1', 'encodings.cp862', 'encodings.iso8859_15', 'encodings.hex_codec',
#     'encodings.cp857', 'encodings.iso8859_4', 'encodings.mac_roman', 'encodings.cp1250',
#     'encodings.iso8859_9', 'encodings.mbcs', 'encodings.mac_greek',
#     'encodings.cp1125', 'encodings.koi8_u', 'encodings.cp273', 'encodings.big5hkscs', 'encodings.cp1140',
#     'encodings.utf_8_sig', 'encodings.iso8859_13', 'encodings.tis_620', 'encodings.cp037',
#     'encodings.iso2022_jp_3', 'encodings.cp861', 'encodings.mac_farsi', 'encodings.iso8859_1',
#     'encodings.cp869', 'encodings.iso8859_8', 'encodings.unicode_internal',
#     'encodings.iso8859_3', 'encodings.cp720', 'encodings.koi8_r', 'encodings.cp437', 'encodings.cp858',
#     'encodings.euc_kr', 'encodings.iso8859_2', 'encodings.cp1251', 'encodings.cp950', 'encodings.gbk',
#     'encodings.cp775', 'encodings.unicode_escape', 'encodings.quopri_codec', 'encodings.cp860',
#     'encodings.koi8_t', 'encodings.uu_codec', 'encodings.cp1253', 'encodings.iso8859_5',
#     'encodings.mac_centeuro', 'encodings.iso8859_11', 'encodings.iso8859_16', 'encodings.iso8859_10',
#     'encodings.gb2312', 'encodings.iso2022_jp', 'encodings.mac_turkish',
#     'encodings.cp1255', 'encodings.cp949', 'encodings.cp1258', 'encodings.punycode'))

# Also some other modules may be safely left out (save ~2MB on linux64/python3.7)
# excludes.extend(('bz2', 'curses', 'decimal', 'grp', 'gzip', 'json', 'lzma', 'pdb', 'pkg_resources',
#     'plistlib', 'pyexpat', 'readline', 'termios', 'uuid', 'xml', 'zlib'))

block_cipher = None
CONSOLE=True

if not USE_NUMPY:
    # Apparently unittes is required??? by numpy
    excludes.extend(("numpy", "unittest"))

hiddenimports=[]

a = Analysis(
    ['run'],
    pathex=[],
    binaries=[],
    datas=[("docs", "docs"),],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    # Must remain True or it will assume a single-file deploy
    exclude_binaries=True,
    name='websockify',
    debug=DEBUG,
    strip=False,
    upx=False,
    console=CONSOLE
)
coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=False, name='websockify'
)

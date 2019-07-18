#!/usr/bin/env python

import argparse
import struct
import sys

def auto_int(x):
    return int(x, 0)

def decompress_mio0(raw_bytes):
    magic = raw_bytes[:4]
    assert magic == b'MIO0'

    uncompressed_size, lengths_offs, data_offs = struct.unpack('>LLL', raw_bytes[4:16])
    flags_offs = 0x10

    output = b""
    while True:
        command_byte = raw_bytes[flags_offs]
        flags_offs += 1

        for i in reversed(range(8)):
            if command_byte & (1 << i):
                # Literal
                uncompressed_size -= 1
                output += bytes([raw_bytes[data_offs]])
                data_offs += 1
            else:
                # LZSS
                tmp, = struct.unpack('>H', raw_bytes[lengths_offs:lengths_offs+2])
                lengths_offs += 2

                window_offset = (tmp & 0x0FFF) + 1
                window_length = (tmp >> 12) + 3
                uncompressed_size -= window_length
                for j in range(window_length):
                    output += bytes([output[-window_offset]])

            if uncompressed_size <= 0:
                return output

def print_hex_dump(raw_bytes):
    count = 0
    for b in raw_bytes:
        if count % 16 == 0:
            print(' ' * 4, end="")
        print('{:02x} '.format(b), end="")
        count += 1
        if count % 16 == 0:
            print()
    if count % 16:
        print()

def pw64_dump_filesys(fname, startOffset, hexSize):
    def hexdump(raw_bytes):
        if hexSize > 0:
            if len(raw_bytes) > hexSize:
                raw_bytes = raw_bytes[:hexSize]
            print_hex_dump(raw_bytes)

    with open(fname, 'rb') as fin:
        fin.seek(startOffset)
        dumping = True
        while (dumping):
            fileOffset = fin.tell()
            print('0x%06X|%06X: ' % (fileOffset, fileOffset - startOffset), end="")
            magic = fin.read(4)
            magicInt = int.from_bytes(magic, byteorder='big')
            if magicInt == 0:
                print('00000000 [EOF]')
                break
            magicStr = magic.decode('ascii')
            if magicStr == 'FORM':
                formLength = int.from_bytes(fin.read(4), byteorder='big')
                formEnd = fin.tell() + formLength
                print('%s: 0x%06X (end: 0x%06X)' % (magicStr, formLength, formEnd))

                fileOffset = fin.tell()
                blockType = fin.read(4).decode('ascii')
                print('0x%06X|%06X: ' % (fileOffset, fileOffset - startOffset), end="")
                print("  %s" % blockType);

                while (fin.tell() < formEnd):
                    fileOffset = fin.tell()
                    print('0x%06X|%06X: ' % (fileOffset, fileOffset - startOffset), end="")
                    magicStr = fin.read(4).decode('ascii')

                    if magicStr in ['NAME', 'INFO', 'JPTX', 'MDBG']:
                        length = int.from_bytes(fin.read(4), byteorder='big')
                        info = fin.read(length)
                        infoStr = info.decode('ascii').rstrip('\0')
                        print('  %s: 0x%06X: %s' % (magicStr, length, infoStr))
                    elif magicStr == 'GZIP': # not actually gzip, but MIO0 container
                        gzipLength = int.from_bytes(fin.read(4), byteorder='big')
                        absOffset = fin.tell() + gzipLength
                        decompType = fin.read(4)
                        decompTypeStr = decompType.decode('ascii')
                        decompLength = int.from_bytes(fin.read(4), byteorder='big')

                        compBytes = fin.read(gzipLength - 8)
                        decompBytes = decompress_mio0(compBytes)

                        print('  %s: 0x%06X: %s' % (magicStr, gzipLength, decompTypeStr))
                        hexdump(decompBytes)
                    # generic handler for lengths that are not yet parsed
                    elif magicStr == 'COMM':
                        length = int.from_bytes(fin.read(4), byteorder='big')
                        sectionData = fin.read(length)
                        print('  %s: 0x%06X:' % (magicStr, length))
                        if blockType == 'UVSQ':
                            count = int(sectionData[0])
                            uvsq = '>Hf'
                            # +1 becuase last u16/float might be special
                            for i in range(count + 1):
                                (idx, val) = struct.unpack(uvsq, sectionData[1+6*i:7+6*i])
                                print('    0x%04X: %f' % (idx, val))
                        else:
                            hexdump(sectionData)
                    # generic handler for lengths that are not yet parsed
                    elif magicStr in ['PART', 'STRG', 'FRMT', 'ESND',
                                      'TPAD', 'CNTG', 'HOPD', 'LWIN', 'LSTP',
                                      'TARG', 'FALC', 'BALS', 'HPAD', 'BTGT',
                                      'THER', 'PHTS', 'SIZE', 'DATA', 'QUAT',
                                      'XLAT', 'PHDR', 'RHDR', 'PPOS', 'RPKT',
                                      '.CTL', '.TBL',
                                      'SCPP', 'SCPH', 'SCPX', 'SCPY', 'SCPR', 'SCPZ', 'SCP#',
                                      'LEVL', 'RNGS', 'BNUS', 'WOBJ', 'LPAD', 'TOYS', 'TPTS', 'APTS',
                                      'TEXT', 'PIID', 'RELA', 'SCPT', #F1WGP
                                      'UVPX', 'UVMO', 'UVDS', 'UVTX', 'UVTR', 'UVCT', 'UVMD', #F1WGP
                                      'FTKL', 'UVEN', 'UVRW', 'STRY', 'UVBT', 'UVFT', 'UVSX', #F1WGP
                                      'UVMS', 'UVMB', 'UVTS', 'UVTP', #F1WGP
                                      'UVAN', 'SEQS']: #F1WGP2
                        length = int.from_bytes(fin.read(4), byteorder='big')
                        sectionData = fin.read(length)
                        print('  %s: 0x%06X:' % (magicStr, length))
                        hexdump(sectionData)
                    # PAD always seems to be 4 bytes of 0 - ignore it
                    elif magicStr in ['PAD ']:
                        length = int.from_bytes(fin.read(4), byteorder='big')
                        print('  %s: 0x%06X:' % (magicStr, length))
                        fin.seek(length, 1)
                    else:
                        nextInt = int.from_bytes(fin.read(4), byteorder='big')
                        print('unknown magic: %s [%08X]' % (magicStr, nextInt))
                        dumping = False
                        return
            else:
                print('unknown top magic: ' + ''.join('{:02x}'.format(x) for x in magic) + ' "' + magicStr + '"')
                dumping = False
                return

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Pilotwings 64 File System Dumper')
    ap.add_argument('file', help='File path of input')
    ap.add_argument('-s', '--start', dest='startOffset', type=auto_int, default=0x0DF5B0, help='Start offset of file system')
    ap.add_argument('-x', '--hex', dest='hexSize', type=auto_int, default=0x60, help='Size of hexdump for unparsed sections')
    args = ap.parse_args()
    pw64_dump_filesys(args.file, args.startOffset, args.hexSize)

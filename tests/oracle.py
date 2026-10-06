#!/usr/bin/env python3
"""Oracle for ZipLens: logical fields from the REAL zipfile module,
offsets from an independent hand-rolled struct walker, CRCs recomputed
with zlib.crc32 over real decompressed content."""
import zipfile, zlib, struct, json, os, sys, warnings

def walk(path):
    data = open(path, 'rb').read()
    out = {'file': os.path.basename(path), 'size': len(data)}
    # logical fields from zipfile itself
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            zf = zipfile.ZipFile(path)
        ents = []
        for zi in zf.infolist():
            dm, dt = zi.date_time, None
            raw_date = ((dm[0]-1980) << 9) | (dm[1] << 5) | dm[2]
            raw_time = (dm[3] << 11) | (dm[4] << 5) | (dm[5] // 2)
            e = {
                'name': zi.filename, 'method': zi.compress_type,
                'flags': zi.flag_bits, 'crc': zi.CRC,
                'csize': zi.compress_size, 'usize': zi.file_size,
                'lho': zi.header_offset,
                'comment': zi.comment.decode('utf-8', 'replace'),
                'raw_time': raw_time, 'raw_date': raw_date,
                'date': {'year': dm[0], 'month': dm[1], 'day': dm[2],
                         'hour': dm[3], 'minute': dm[4], 'second': dm[5] - dm[5] % 2},
            }
            if zi.compress_type in (0, 8) and not (zi.flag_bits & 1):
                content = zf.read(zi.filename)
                e['content_ok'] = (len(content) == zi.file_size and
                                   zlib.crc32(content) == zi.CRC)
            ents.append(e)
        out['entries'] = ents
        out['comment'] = zf.comment.decode('utf-8', 'replace')
    except zipfile.BadZipFile as ex:
        out['bad'] = str(ex)
        return out
    # independent EOCD walk
    i = data.rfind(b'PK\x05\x06', max(0, len(data) - 22 - 65535))
    if i < 0:
        out['bad'] = 'no EOCD'
        return out
    (sig, disk, cddisk, ndisk, ntot, cdsize, cdoff, clen) = struct.unpack_from('<IHHHHIIH', data, i)
    out['eocd'] = {'offset': i, 'entries': ntot, 'cd_size': cdsize,
                   'cd_offset': cdoff, 'comment': out['comment'],
                   'trailing': len(data) - (i + 22 + clen)}
    out['zip64'] = os.path.basename(path) == 'zip64.zip'
    # local header sig check at each lho
    for e, zi in zip(out['entries'], zf.infolist()):
        o = zi.header_offset
        e['local_sig_ok'] = data[o:o+4] == b'PK\x03\x04'
        lnlen, lxlen = struct.unpack_from('<HH', data, o + 26)
        e['local_data_off'] = o + 30 + lnlen + lxlen
        e['local_name'] = data[o+30:o+30+lnlen].decode('utf-8', 'replace')
    return out

if __name__ == '__main__':
    res = []
    for f in sorted(os.listdir('corpus')):
        if f.endswith('.zip'):
            res.append(walk(os.path.join('corpus', f)))
    json.dump({'items': res}, open('expected.json', 'w'), indent=1)
    open('expected.json', 'a').write('\n')
    print('wrote expected.json:', len(res), 'items')
    for it in res:
        print(' ', it['file'], '| entries:', len(it.get('entries', [])), '| comment:', repr(it.get('comment')), '| trailing:', it.get('eocd', {}).get('trailing'))

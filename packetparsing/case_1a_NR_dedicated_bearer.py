import pyshark
import os
import time
from xlsxwriter.workbook import Workbook


tz = str(time.strftime("%z", time.gmtime()))
pcapfiles = []
for files in os.listdir('out'):
    if files.find('.pcap')>=0:
        pcapfiles.append(files)


def chk4gOr5gCall(filename,containString,field):
    filelocation = 'out\\'+filename
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=f'_ws.col.info contains \"{containString}\"')
    cap.load_packets()
    typeOfCall = ''
    if cap:
        pkt = cap[0]
        print(pkt.layers)
        invite_arrival_time = pkt.sniff_time
        print(invite_arrival_time)
        typeOfCall = pkt.sip._all_fields['sip.P-Access-Network-Info.access-type']
        return {'callType':typeOfCall,'inviteTime':invite_arrival_time}
    else:
        return None
    #print(f'Number of invite packets in {filename}: {len(cap)}')

def chkPDUSesResModReqAnd5QI(filelocation, containString, field):
    filelocation = 'out\\' + filename
    filt = f'_ws.col.info contains \"{containString}\"'
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=filt)
    cap.load_packets()
    if cap:
        pkt = cap[0]
        try:
            return {'PDUSesResModReq':'PDUSessionResourceModifyRequest','5qi':pkt.ngap._all_fields['ngap.fiveQI']}
        except:
            return {'PDUSesResModReq':'PDUSessionResourceModifyRequest','5qi':99}
    else:
        return None #{'PDUSesResModReq':'N/A','5qi':'N/A'}

wb = Workbook('out/out.xlsx')
ws = wb.add_worksheet('5GDedicatedBearer')
ws.set_tab_color('#0062AC')
cell_format_header = wb.add_format(
    {'bold': True, 'font_color': 'white', 'bg_color': '#0062AC', 'border': 1, 'border_color': 'white'})

cell_format_header.set_font_size(10)
cell_format_data = wb.add_format()
cell_format_data.set_font_size(8)

colheader = ['sourcePcap',
             'problematicCallId',
             'inviteTime',
             'callType',
             'messageType',
             '5QI',
             'comment',
             ]
ws.set_column(0, 0, 12)
ws.set_column(1, 1, 20)
ws.set_column(2, 1, 20)
ws.set_column(3, 2, 12)
ws.set_column(4, 3, 25)
ws.set_column(5, 4, 5)
ws.set_column(6, 5, 35)


row = 0
for header in colheader:
    ws.write(row, colheader.index(header), header, cell_format_header)

for filename in pcapfiles:

    print(f'Working with {filename}')
    row += 1
    callTypeInfo = chk4gOr5gCall(filename,'Request: INVITE','sip.P-Access-Network-Info.access-type')
    pduInfo = chkPDUSesResModReqAnd5QI(filename, 'PDUSessionResourceModifyRequest', 'ngap.fiveQI')
    print(pduInfo)
    ws.write(row, 0, filename.split('.')[0].split('_')[0], cell_format_data)
    ws.write(row, 1, filename.split('.')[0].split('_')[1], cell_format_data)
    ws.write(row, 2, str(callTypeInfo['inviteTime']), cell_format_data)
    ws.write(row, 3, callTypeInfo['callType'], cell_format_data)

    if callTypeInfo['callType'].find('3GPP-NR-')>=0:
        if pduInfo:
            ws.write(row,4,pduInfo['PDUSesResModReq'],cell_format_data)
            ws.write(row,5,pduInfo['5qi'],cell_format_data)
            ws.write(row,6,'More steps to check',cell_format_data)
        else:
            ws.write(row,4,'N/A',cell_format_data)
            ws.write(row,5,'N/A',cell_format_data)
            ws.write(row,6,'No dedicated bearer from core',cell_format_data)

    else:
        ws.write(row, 4, 'Not analysed', cell_format_data)
        ws.write(row, 5, 'Not analysed', cell_format_data)
        ws.write(row, 6, 'Not analysed', cell_format_data)
wb.close()
os.system('start out/out.xlsx')
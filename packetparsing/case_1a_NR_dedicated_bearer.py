import pyshark
import os
import time
from xlsxwriter.workbook import Workbook


tz = str(time.strftime("%z", time.gmtime()))
pcapfiles = []
for files in os.listdir('out'):
    if files.find('.pcap')>=0:
        pcapfiles.append(files)


def chk4gOr5gCall(filename,containString,containString2,field):

    filelocation = 'out\\'+filename
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=f'_ws.col.info contains \"{containString}\"')
    cap.load_packets()
    cap2 = pyshark.FileCapture(f'{filelocation}', display_filter=f'_ws.col.info contains \"{containString2}\"')
    cap2.load_packets()

    typeOfCall = ''
    if cap:
        pkt = cap[0]
        invite_arrival_time = pkt.sniff_time

        try:
            typeOfCall = pkt.sip._all_fields['sip.P-Access-Network-Info.access-type']
        except KeyError:
            typeOfCall = cap2[0].sip._all_fields['sip.P-Access-Network-Info.access-type']
        except:
            typeOfCall = 'Unknown'

        return {'callType':typeOfCall,'inviteTime':invite_arrival_time}
    else:
        return None

def chkPDUSesResModReqAnd5QI(filename, containString, field):
    filelocation = 'out\\' + filename
    filt = f'_ws.col.info contains \"{containString}\"'
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=filt)
    cap.load_packets()
    if cap:
        pkt = cap[0]
        resp = chkPDUSesResModResponse(filename,'PDUSessionResourceModifyResponse')
        try:
            #return {'PDUSesResModReq':'PDUSessionResourceModifyRequest','5qi':pkt.ngap._all_fields['ngap.fiveQI']}
            return {'PDUSesResModReq': 'PDUSessionResourceModifyRequest', 'msg': resp['msg'], 'comment':resp['comment']}
        except:
            #return {'PDUSesResModReq':'PDUSessionResourceModifyRequest','5qi':99}
            return {'PDUSesResModReq': 'PDUSessionResourceModifyRequest', 'resp': 'unknown'}

    else:
        return None #{'PDUSesResModReq':'N/A','5qi':'N/A'}

def chkTAUMasg(filename, continString):
    filelocation = 'out\\'+filename
    filt = f'_ws.col.info contains \"{continString}\"'
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=filt)
    cap.load_packets()
    if cap:
        return True
    return False

def chkPDUSesResModResponse(filename, containString):
    filelocation = 'out\\'+filename
    filt = f'_ws.col.info contains \"{containString}\"'
    cap = pyshark.FileCapture(f'{filelocation}', display_filter=filt)
    cap.load_packets()


    pkt = cap[0]
    msg = pkt.ngap._all_fields['ngap.radioNetwork']

    comment = ''
    #radioNetwork: xn-handover-triggered (33)
    #radioNetwork: ims - voice - eps - fallback - or -rat - fallback - triggered(36)
    if msg=='33':
        msg = 'radio network: xn-handover-triggered(33)'
        comment = 'gNB responded with xn-handover-triggered'
    elif msg=='36':
        msg = 'radio network: ims-voice-eps-fallback-or-rat-fallback-triggered(36)'
        isTAUExists = chkTAUMasg(filename,'Tracking area update')
        if isTAUExists:
            comment = 'TAU msg after EPS FB, Need to check further'
        else:
            comment = 'No TAU msg after EPS FB'
    else:
        msg = 'unknown'
        comment = 'unknown'
    return {'msg':msg, 'comment':comment}

#def chk5QI()

wb = Workbook('out/out.xlsx')
ws = wb.add_worksheet('WiresharkParsedInfo')
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
             'response',
             'comment',
             ]



row = 0
for header in colheader:
    ws.write(row, colheader.index(header), header, cell_format_header)

for filename in pcapfiles:

    print(f'Working with {filename}')
    row += 1
    callTypeInfo = chk4gOr5gCall(filename,'Request: INVITE','Status: 183 Session Progress',"sip.P-Access-Network-Info.access-type")
    pduInfo = chkPDUSesResModReqAnd5QI(filename, 'PDUSessionResourceModifyRequest', 'ngap.fiveQI')

    source_file = '_'.join(filename.split('.')[0].split('_')[:-1])
    ws.write(row, 0, source_file, cell_format_data)
    ws.write(row, 1, filename.split('.')[0].split('_')[-1], cell_format_data)
    ws.write(row, 2, str(callTypeInfo['inviteTime']), cell_format_data)
    ws.write(row, 3, callTypeInfo['callType'], cell_format_data)

    if callTypeInfo['callType'].find('3GPP-NR-')>=0:
        if pduInfo:
            ws.write(row,4,pduInfo['PDUSesResModReq'],cell_format_data)
            ws.write(row,5,pduInfo['msg'],cell_format_data)
            ws.write(row,6,pduInfo['comment'],cell_format_data)
        else:
            ws.write(row,4,'N/A',cell_format_data)
            ws.write(row,5,'N/A',cell_format_data)
            ws.write(row,6,'No dedicated bearer from core',cell_format_data)

    else:
        ws.write(row, 4, 'Not analysed', cell_format_data)
        ws.write(row, 5, 'Not analysed', cell_format_data)
        ws.write(row, 6, 'Not analysed', cell_format_data)
ws.set_column(0, 0, 14)
ws.set_column(1, 1, 20)
ws.set_column(2, 2, 20)
ws.set_column(3, 3, 12)
ws.set_column(4, 4, 22)
ws.set_column(5, 5, 40)
ws.set_column(6, 6, 30)
wb.close()
os.system('start out/out.xlsx')
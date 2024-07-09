# Author:        Tapon Paul, tapon.paul@nokia.com
# Created:       04/07/2024
# Version:       1.2 (Edited to work independent of timezone)
# Instruction:   make sure you have wireshark installed with tshark
#                to run this code.

#-----------------------------------------------------------------------
import os
import sys

import pyshark
import time

tz = str(time.strftime("%z", time.gmtime()))

try:
    os.makedirs('out')
except FileExistsError:
    pass

pcapfiles = []
for files in os.listdir(os.getcwd()):
    if files.find('.pcap')>=0:
        pcapfiles.append(files)

print(f'Following pcap file(s) will be parsed one by one \n{pcapfiles}')

for pcapfile in pcapfiles:
    print(f"\n\n**** Preparing sorted version of source file {pcapfile} ****")
    filename = pcapfile
    os.system(f'reordercap.exe {filename} out\\Sorted_{filename}')
    print('\nGrabing SIP with status code 500')
    cap = pyshark.FileCapture(f'{filename}', display_filter="sip.Status-Code == 500")
    cap.load_packets()
    print(f'Total {len(cap)} SIP packets found with status code 500')
    if not cap:
        os.remove(f'out\\Sorted_{filename}')
        continue
    call_ids = []
    for pkt in cap:
        #call_id = (str(pkt.raw_sip).split('\r\n')[6]).split(':')[-1][:-4]
        call_id = pkt.sip._all_fields['sip.Call-ID']
        if call_id not in call_ids:
            call_ids.append(call_id)
    print(f'\nFollowing distinct call ids found in {filename}\n{[x.split(" ")[-1] for x in call_ids]}')
    for call_id in call_ids:
        call_id = call_id.split(' ')[-1] # removing non ascii characters
        filt = str(f"raw_sip.line contains \"Call-ID: {call_id}\"")
        print(f'\n\nWorking with {call_id}')
        cap2 = pyshark.FileCapture(f'{filename}', display_filter=filt, output_file='out\\temp1.pcap')
        cap2.load_packets()
        start_packet = cap2[0]
        end_packet = cap2[-1]
        cap2.close()
        st_time = start_packet.sniff_time
        end_time = end_packet.sniff_time
        print(f'start_time: {st_time} and end_time: {end_time}')
        print(f'Filtering packets arrived in between {st_time} and {end_time}')
        filt = f'frame.time >= "{st_time}{tz}" && frame.time <= "{end_time}{tz}"'
        cap3 = pyshark.FileCapture(f'out\\Sorted_{filename}',display_filter=filt,output_file=f'out\\{filename.split(".")[0]}_{call_id.strip()}.pcap')
        cap3.load_packets()
        print(f'Total {len(cap3)} packets found for call id {call_id}')
    os.remove(f'out\\Sorted_{filename}')
    os.remove(f'out\\temp1.pcap')
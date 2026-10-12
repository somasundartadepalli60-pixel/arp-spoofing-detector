"""Run after starting arp_spoofing_detector.py. Local demo only; no spoofing on the network."""
import argparse
from pathlib import Path
from demo_bridge import submit_request

def run_simulation(target_ip=None, fake_mac=None, directory=None):
    request,path=submit_request(directory or Path(__file__).resolve().parent/'.local_demo',target_ip,fake_mac)
    print('LOCAL ARP CONFLICT DEMO - not a real network attack')
    print('Claimed baseline IP:',request['claimed_ip'])
    print('Simulated changed MAC:',request['fake_mac'])
    print('Submitted to the running detector. Check its dashboard, logs and configured receiver email.')
    print('No packets transmitted and no real passwords collected.')
    return request

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Trigger a labelled local ARP conflict in the running detector.')
    parser.add_argument('target_ip',nargs='?',help='Existing baseline IP; defaults to its first entry')
    parser.add_argument('--fake-mac',help='Changed unicast MAC; a new random local MAC is used by default')
    args=parser.parse_args()
    try:run_simulation(args.target_ip,args.fake_mac)
    except ValueError as exc:parser.exit(1,str(exc)+'\n')

"""Offline checks. No network capture or email sending."""
import tempfile
import unittest
from pathlib import Path
from scapy.all import ARP, Ether
from detector_core import Detector, parse_arp, AlertLogger
from report_generator import build_report

class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.info={'my_ip':'192.0.2.10','my_mac':'00:22:33:44:55:66','interface':'offline'}
        self.d=Detector({'192.0.2.1':'aa:bb:cc:dd:ee:ff'},self.info)
    def packet(self,mac,ip='192.0.2.1'):
        return Ether(src='aa:bb:cc:dd:ee:ff')/ARP(op=2,psrc=ip,hwsrc=mac,pdst='192.0.2.10',hwdst=self.info['my_mac'])
    def test_packet_conflict_and_dedup(self):
        row,event=self.d.process(self.packet('02:00:00:00:00:fe'))
        self.assertTrue(row['conflict']);self.assertIsNotNone(event)
        self.assertIsNone(self.d.process(self.packet('02:00:00:00:00:fe'))[1])
    def test_cache_and_packet_share_dedup(self):
        events=self.d.process_cache({'192.0.2.1':'02:00:00:00:00:fe'})
        self.assertEqual(len(events),1);self.assertTrue(events[0]['ether_mac'].startswith('Unknown'))
        self.assertIsNone(self.d.process(self.packet('02:00:00:00:00:fe'))[1])
    def test_unknown_and_unchanged(self):
        self.assertEqual(self.d.process_cache({'192.0.2.99':'02:00:00:00:00:fe'}),[])
        self.assertIsNone(self.d.process(self.packet('aa:bb:cc:dd:ee:ff'))[1])
    def test_adapter_cache_filtering(self):
        text='Interface: 192.0.2.10 --- 0x6\n192.0.2.1 aa-bb-cc-dd-ee-ff dynamic\nInterface: 10.0.0.2 --- 0x7\n10.0.0.1 00-11-22-33-44-55 dynamic'
        self.assertEqual(parse_arp(text,local_ip='192.0.2.10'),{'192.0.2.1':'aa:bb:cc:dd:ee:ff'})
    def test_logging_and_pdf(self):
        event=self.d.process(self.packet('02:00:00:00:00:fe'))[1]
        with tempfile.TemporaryDirectory() as tmp:
            logger=AlertLogger(tmp);logger.write(event)
            self.assertIn('192.0.2.1',logger.read())
            for template in (False,True):
                path=Path(tmp)/f'report_{template}.pdf'
                build_report(path,{'info':self.info,'events':[event],'baseline':self.d.baseline},template=template)
                self.assertTrue(path.read_bytes().startswith(b'%PDF'))

if __name__=='__main__':unittest.main(verbosity=2)

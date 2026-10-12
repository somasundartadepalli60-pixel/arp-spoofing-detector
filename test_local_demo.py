"""Offline local demonstration tests: no network packets or emails."""
import tempfile,time,queue,unittest
from pathlib import Path
from demo_bridge import create_session,submit_request,take_requests,end_session
from detector_core import LocalDemoMonitor
from scapy.all import Ether,ARP
class LocalDemoTests(unittest.TestCase):
    def test_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=create_session(tmp,{'192.0.2.1':'02:00:00:00:00:01'},{})
            request,path=submit_request(tmp)
            self.assertTrue(path.exists())
            self.assertEqual(len(list(take_requests(tmp,session))),1)
            self.assertFalse(path.exists());end_session(tmp)
            with self.assertRaises(ValueError):submit_request(tmp)
    def test_unknown_ip_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            create_session(tmp,{'192.0.2.1':'02:00:00:00:00:01'},{})
            with self.assertRaises(ValueError):submit_request(tmp,'192.0.2.99')
    def test_demo_does_not_suppress_real_conflict(self):
        q=queue.Queue();events=[];m=LocalDemoMonitor(None,q,events.append);m.start()
        deadline=time.monotonic()+2
        while not m.detector and time.monotonic()<deadline:time.sleep(.01)
        try:
            self.assertTrue(m.process_demo('192.0.2.1','02:11:22:33:44:55'))
            self.assertFalse(m.process_demo('192.0.2.1','02:11:22:33:44:55'))
            self.assertTrue(events[0]['simulation'])
            row,event=m.detector.process(Ether()/ARP(op=2,psrc='192.0.2.1',hwsrc='02:11:22:33:44:55'))
            self.assertIsNotNone(event)
        finally:m.stop();m.join(2)
if __name__=='__main__':unittest.main(verbosity=2)

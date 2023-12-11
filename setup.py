from setuptools import setup

setup(
    name = 'lumina',
    version = '0.4',
    description = "A tool to test performance and correctness of RDMA NICs",
    author = 'Zhuolong Yu, Wei Bai, Bowen Su',
    author_email = 'yuzhuolong1993@gmail.com, baiwei0427@gmail.com, subowen2001@gmail.com',
    packages = ['lumina',
                'lumina.orchestrator',
                'lumina.analyzer',
                'lumina.analyzer.checker',
                'lumina.analyzer.packet_parser',
                'lumina.analyzer.counter',
                'lumina.analyzer.pcap_processor',
                'lumina.analyzer.measurer',
                'lumina.e2e_test',
                'lumina.utils'],
    package_dir = {'lumina' : 'lumina',
                   'lumina.orchestrator'           : 'lumina/orchestrator',
                   'lumina.analyzer'               : 'lumina/analyzer',
                   'lumina.analyzer.checker'       : 'lumina/analyzer/checker',
                   'lumina.analyzer.packet_parser' : 'lumina/analyzer/packet_parser',
                   'lumina.analyzer.counter'       : 'lumina/analyzer/counter',
                   'lumina.analyzer.pcap_processor': 'lumina/analyzer/pcap_processor',
                   'lumina.analyzer.measurer'      : 'lumina/analyzer/measurer',
                   'lumina.e2e_test'               : 'lumina/e2e_test',
                   'lumina.utils'                  : 'lumina/utils'},
    scripts = ['bin/lumina-orch',
               'bin/lumina-analyzer',
               'bin/lumina-test-gbn',
               'bin/lumina-test-cnp'],
    install_requires = [
        'paramiko',
        'scp',
        'dpkt',
        'pyyaml>=6.0'
    ]
)

# Lumina
Lumina is a testing tool for hardware network stacks like RDMA. 
It leverages network programmability to emulate various network scenarios at line rate.
Lumina has four components:
1. **Orchestrator**
   To run a test, the orchestrator takes a configuration as input, sets up the environment and coordinates the execution of different components.
2. **Traffic generator**
   Lumina employs two hosts with the same bandwidth capacity to generate traffic. Both hosts are equipped with the hardware network stack under test and are running separate instances of a traffic generator. One host serves as the requester, while the other functions as the responder. These hosts collaboratively generate network traffic based on the configurations provided by the orchestrator
3. **Event injector**
   The event injector serves the purpose of forwarding traffic while also injecting pre-configured events like ECN marks, packet losses, and corruptions. 
4. **Traffic dumper**
   The event injector mirrors all RDMA packets to the traffic dumpers allowing for offline analysis at a later stage.
## Testbed requirements
- Hardware requirement
  - A top-of-rack Tofino switch.
  - Two servers installed with under-test RDMA NIC (currently we support NVIDIA/Mellanox Connect-X 4-Lx, NVIDIA/Mellanox Connect-X 5, NVIDIA/Mellanox Connect-X 6-Dx  and Intel E810).
  - Two servers that support DPDK and possess a total throughput larger or equal to that of the RDMA NIC servers mentioned above.
- Software requirement
  
  The current version of Lumina has been tested on:
  - Switch: BF SDE 9.4.0.
  - Under test servers: 
    - NVIDIA/Mellanox NIC: MLNX_OFED_LINUX-5.8-1.1.2.1-LTS
    - Intel E810: ice 1.9.11 and irdma 1.9.30
  - Mirror servers: DPDK 20.11.
PFC is disabled on both the switch and NICs. 

## Setup
We suggest to create a virtual environment before installing Lumina: [Creation of virtual environments](https://docs.python.org/3/library/venv.html)
- Update setuptools to the latest version: `pip3 install --upgrade setuptools`
- Install Lumina: `python3 setup.py install`

Testcases are written as yaml files. The yaml file should include the log-in credential for each component and parameter settings for the specific testcase. We recommend using SSH key-based authentication for passwordless login. Please check this [example](conf/example.yml).

## Usage
After installation, four files will be generated in `./bin` folder: `lumina-analyzer`, `lumina-orch`, `lumina-test-cnp`, `lumina-test-gbn`. 
- Test with a configuration file: `python3 bin/lumina-orch -f [configuration (yaml) file name]`
- Test with all the configuration files in a folder: `python3 bin/lumina-orch -d [folder name]`
  
You can replace `bin/lumina-orch` with `bin/lumina-test-cnp` or `bin/lumina-test-gbn`. `lumina-test-cnp` and `lumina-test-gbn` will do some necessary checking and analyzing for CNP testing and retransmission testing respectively, after experiment finishes.

## Citation

```
@inproceedings {lumina-yu,
    author = {Yu, Zhuolong and Su, Bowen and Bai, Wei and Raindel, Shachar and Braverman, Vladimir and Jin, Xin},
    title = {Understanding the Micro-Behaviors of Hardware Offloaded Network Stacks with Lumina},
    booktitle = {Proceedings of the ACM SIGCOMM 2023 Conference},
    year = {2023}
}
```

     --^--
    /^ ^ ^\
       | O R B I T
       |
     | | http://www.orbitproject.eu/
      U

This branch is a modified version of the COLO fault-tolerance scheme.
It's very much a work-in-progress.
It contains:
  * The COLO Framework v2.4 set from https://github.com/coloft/qemu.git
    including the block code from branch colo-v2.4-periodic-mode
  * The userspace colo proxy from the December 2015 release of
    https://github.com/zhangckid/qemu.git 
      branch colo-v2.2-periodic-mode-with-colo-proxyV2
    including most of the integration code.

The following patches added as part of the ORBIT work:
  * HMP equivalent commands for x-blockdev-change
  * RDMA transport modifications for COLO
  * A patch to use pthread_condwait to notify the main colo thread of miscompares
  * Hybrid mode that switches between COLO and simple checkpointing
  * Checkpoint statistics using QEMUs TimedAverage

# FU_Hypervisor
A hypervisor hiding user-mode memory using EPT



/*
TODO:
- wanna map patch_address to the kernel space using MmProbeAndLockPages
- multi-page handling
- create sample hook projects: local hook with minihook (C), and remote hook 
    with EasyHook (C++)

BUG:
- Full dmp aquision never ends
*/


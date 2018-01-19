# ExportForensicVM
This program exports a VMware VM for security forensic purposes. 
Snapshots a VM with memory snapshot, creates a linked clone based on the snapshot, then exports the VM as an OVF.

TODO: This program works for small sized VMs, however, the process of exporting a VM takes a significant amount of time. Testing the export via powerCLI iwth the Export-Vapp cmdlet completes in a far greater amount of time. The hhtp_nfc_lease used via java or powerCLI is the same process for python, however, in python the process is incredibly slow. Investigation is required to determine if this can be fixed.

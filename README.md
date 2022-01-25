# RefleXXion
RefleXXion is a utility designed to aid in bypassing user-mode  hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks, it first collects the syscall numbers of the NtOpenFile, NtCreateSection, NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array. 

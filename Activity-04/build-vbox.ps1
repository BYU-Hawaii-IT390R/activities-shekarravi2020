# Set variables
$vmName = "AutomatedWin10"
$isoPath = "C:\Users\sheka\OneDrive\Desktop\GithubRepo\Activity4\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO = "C:\Users\sheka\OneDrive\Desktop\GithubRepo\Activity4\output\answer.iso"
$vdiPath = "C:\Users\sheka\OneDrive\Desktop\GithubRepo\Activity4\AutomatedWin10.vdi"

# Create VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name $vmName --register
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"

# Create hard disk
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename $vdiPath --size 40000

# Add storage controllers and attach drives
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $vdiPath

& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "IDE Controller" --add ide
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium $isoPath
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium $answerISO

# Enable networking
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --nic1 nat

# Start the VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vmName

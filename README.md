# Virus_total
Python 3 program (soon for Python 2 too) which utilizes virus total API 
Using this program we can check the authenticity of
hashes (currently MD5) 
1. find the hash of the file specified
2. upload hash to virusTotal
3. as report will be returned which will can be saved
 and any specific detection will be displayed

usage: vt.py [-h] [-s] [-j] HashorPath

Search and Download from VirusTotal

positional arguments:
 HashorPath      Enter the MD5 Hash or Path to File

optional arguments:
 -h, --help      show this help message and exit
 -s, --search    Search VirusTotal
 -j, --jsondump  Dumps the full VT report to file (VTDLXXX.json)

  Git Bash Examples 
  
  hp pc@HP /g/hello_world/VirusTotal_API_Tool (master) 
$ python vt.py -s 'G://hello_world//Actual Spy Keylogger.rar'

        Results for MD5:  503f5b98bb116e2d691df2773d9cd4ec

        Detected by:  0 / 59
        Scanned on: 2017-10-07 19:17:14
 
 hp pc@HP /g/hello_world/VirusTotal_API_Tool (master)
$ python vt.py -j 'G://hello_world//Actual Spy Keylogger.rar'

        Results for MD5:  503f5b98bb116e2d691df2773d9cd4ec

        Detected by:  0 / 59
        Scanned on: 2017-10-07 19:17:14

        JSON Written to File -- VTDL503F5B98BB116E2D691DF2773D9CD4EC.json
 
 
 Thanks! Xen0ph0n for awesome reference, 
 https://github.com/Xen0ph0n/VirusTotal_API_Tool


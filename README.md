# Phishing Attempt Investigation

This project involves investigating a phishing alert triggered by suspicious activity. I inspected the provided PCAP file and analyzed various extracted files to confirm the nature of the attack and answer relevant questions based on the logs and VirusTotal reports.

## Objective

The main objective of this project is to confirm whether the phishing alert is a true positive by analyzing network logs, identifying malicious files, and correlating the findings with VirusTotal reports.

## Skills Learned

- Network traffic analysis using Zeek
- Investigation of malicious executables
- Working with VirusTotal to analyze file properties
- Extraction of malicious indicators from log files
- Use of defanged format for safe representation of indicators

## Tools Used

- **Zeek**: For analyzing PCAP files and extracting HTTP logs.
- **VirusTotal**: For investigating malicious file properties and network communications.
- **Command-line tools**: For parsing and extracting data from logs (`grep`, `cat`, etc.).
- **CyberChef**: For defanging URLs and IP addresses.

## Steps

1. **PCAP Analysis**  
   I used Zeek to inspect the `phishing.pcap` file:
   &&&
   zeek -Cr phishing.pcap
   &&&
   This command extracted HTTP logs and identified suspicious activity from the network traffic.

   ![Image 2](https://github.com/user-attachments/assets/70fb867d-8c23-409e-9abc-c6da07ebb84a)

   *Image 2: Command used to investigate logs with Zeek*

2. **Suspicious Source Address (Defanged Format)**  
   From the logs, I identified the suspicious source address as:
   &&&
   10[.]6[.]27[.]102
   &&&
   The defanged format was used to ensure the safe handling of malicious indicators.

   ![Image 3](https://github.com/user-attachments/assets/f9e8baf3-ba2b-49d5-9ddf-c8867db11f72)
   *Image 3: Defanging the suspicious source IP address*

3. **Malicious Domain from http.log**  
   By examining the `http.log` file, I identified the domain from which the malicious files were downloaded:
   &&&
   smart-fax[.]com
   &&&
   This domain was extracted from the logs using the following command:
   &&&
   cat http.log
   &&&
   
   ![Image 5](https://github.com/user-attachments/assets/636feecb-8bfb-4e8d-ad24-dee920d5b6c9)


   *Image 5: Investigation of the `http.log` file showing the malicious domain*

4. **Malicious Document in VirusTotal**  
   The malicious document associated with the phishing attempt was investigated in VirusTotal. I found it to be a VBA file:
   &&&
   VBA
   &&&
   The document was analyzed using Zeek with the file extraction script:
   &&&
   zeek -Cr phishing.pcap file-extract-demo.zeek
   &&&
   
   ![Image 7](https://github.com/user-attachments/assets/6a843110-bcf1-4a12-9d42-d239c87cb4c6)

  
   *Image 7: File extraction analysis of the malicious VBA document*

5. **Extracted Malicious Executable**  
   I extracted the malicious `.exe` file and found its name in VirusTotal:
   &&&
   PleaseWaitWindow.exe
   &&&
   This analysis helped identify the executable responsible for the phishing attempt.

   ![Image 9]![image](https://github.com/user-attachments/assets/45a605df-cb11-413b-9199-71fad8cd8097)

   *Image 9: Properties of the extracted malicious executable in VirusTotal*

6. **Contacted Domain from Executable (Defanged Format)**  
   The domain contacted by the malicious `.exe` file was found to be:
   &&&
   hopto[.]org
   &&&
   This information was extracted from VirusTotal.

   ![Image 11](https://github.com/user-attachments/assets/67eff265-34f2-4435-9cad-247d61653b36)

   *Image 11: Investigating the contacted domain of the malicious executable*

7. **Request Name of Downloaded Executable**  
   From the `http.log` file, I identified the request name for the downloaded malicious executable as:
   &&&
   knr.exe
   &&&
   This was extracted using:
   &&&
   cat http.log | grep -E '{3}\\{3}'
   &&&
   
   ![Image 12](https://github.com/user-attachments/assets/d0a8d785-bc74-4324-9599-3fe5a07b35ea)

   *Image 12: Request name of the downloaded malicious executable*

## Summary of Findings

- **Source IP**: 10[.]6[.]27[.]102
- **Malicious Domain**: smart-fax[.]com
- **Malicious Document**: VBA file
- **Malicious Executable Name**: PleaseWaitWindow.exe
- **Contacted Domain**: hopto[.]org
- **Downloaded Executable**: knr.exe

## Conclusion

This phishing attempt was confirmed as a true positive. The analysis of the PCAP file, combined with log data and VirusTotal reports, provided strong evidence of malicious activity involving suspicious domains, a VBA document, and an executable that contacted a known malicious domain.

&&&

This project page includes references to each step supported by the images in chronological order of investigation.

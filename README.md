# **yasp**  
Yet Another STIG Parser  
  
STIG / POAM management automation.  

Author: Ashton J. Hanisch < <ajhanisch@gmail.com> >  
  
# **SYNOPSIS**  
Script to help automate STIG / POAM management.

# **DESCRIPTION**  
Script designed to focus on STIG / POAM management and less on individual STIG compliance automation. Designed to help with automated relevant POAM generation and automated statistic calculation and presentation.

# **FEATURES**  
* Built-in POAM Generation. 
  
Generates starter POAM documents from .csv files given to parse. Can be given as many exported STIG .csv files as needed to parse. Documents will contain working digital signature blocks for all needing to sign. Documents generated will be unique to vulnerability. If multiple hosts with the same STIG .csv file sharing multiple vulnerabilities, you will get one POAM for each vulnerability and have all effected hosts listed in that single POAM.  

* Built-in Statistics Generation.  
  
Generates statistics from .csv files given to parse. Can be given as many exported STIG .csv files as needed to parse.  

# **CONSIDERATIONS**  
Depending on which version (.exe or .py) of yasp you choose to use, additional steps may or may not be needed to use yasp. If you choose to use the .exe version, you will NOT need to install Python or any dependencies to start successfully using yasp. If you choose to use the .py version, ensure to have a 3+ version of Python installed in your environment.
  
# **DOCUMENTATION**  
Check out the Wiki for specific guidance using YASP.  

# **USAGE**  
Running the tool:  
.\yasp.exe --input . [options]  
  
Typical Usage Example:  
Generate starter POAM documents:  
.\yasp.exe --input . --poams .\template.docx  
  
Generate statistics:  
.\yasp.exe --input . --stats  
  
Display help menu:  
.\yasp.exe --help  

# HPCredDumper
Simple metasploit module that attempts to dump HP printer web admin credentials

## Installation

Download `hp_printer.py` and copy to `/usr/share/metasploit-framework/modules/auxiliary/scanner/printer`
Then run `reload_all` from the msfconsole if it is already running.

```
> cp hp_printer.py /usr/share/metasploit-framework/modules/auxiliary/scanner/printer
> msfconsole

...

msf6 > use scanner/printer/hp_printer
msf6 auxiliary(scanner/printer/hp_printer) >
```

## Associated CVE

- CVE-2012-5221
[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)



## ptodnes - OSINT Domain Name Enumeration System

## Installation

1. Download latest release whl package from [releases](https://github.com/Penterep/ptodnes/releases/latest) page.
2. Install the package using pip/pipx.
```bash
pipx install <path_to_downloaded_whl_file>
```

Example:
```bash
pipx install ~/Downloads/ptodnes-1.11.1-py3-none-any.whl
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptodnes -l
ptodnes -d example.com
ptodnes -d example.com example.net
ptodnes -d example.com -D VirusTotal CRTsh
ptodnes -d example.com -j -o example -t A AAAA
ptodnes -d example.com -D Wordlist -w /usr/share/wordlists/rockyou.txt
```

## Options
```
-c  --csv                                   Output in CSV format
-C  --config              <config>          Path to config file (default ~/ptodnes.toml)
-d  --domain              <domain ...>      Domains to search for
-D  --datasource          <datasource ...>  Datasources to browse
-e  --exclude-unverified                    Exclude unverified records
-j  --json                                  Output in JSON format
-l  --list                                  List available datasources
-n  --nonxdomain                            Filter results with no DNS data
-o  --output              <file_prefix>     Save results to files (format specification required)
-p  --ptjson                                Output in ptJSONlib format
-q  --query                                 Query domains against DNS servers
-r  --retry               <count>           Number of attempts (default:5)
-t  --type                <type ...>        Types of DNS records to search for
-T  --timeout             <timeout>         Datasource connection timeout (in seconds, default:5)
-v  --version                               Print version and exit
-V  --verbose             <1|2|3|4>         Set verbosity level (1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)
-w  --wordlist            <wordlist ...>    Path to wordlist(s) for wordlist search.
-y  --yaml                                  Output in YAML format

```

## Configuration
Configuration is stored in TOML file. Default location is `~/ptodnes.toml`.

Example configuration:
```toml
[VirusTotal]
api_keys = [
    'API_KEY_1',
    'API_KEY_2'
]

[SecurityTrails]
api_keys = [
    'API_KEY_1',
    'API_KEY_2'
]

[Wordlist]
wordlists = [
'/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt'
]

...
[<Datasource>]
api_keys = [
    '...'
]
```

## Dependencies
```
ptlibs
aiodns
aiohttp
aiopg
pyyaml
```

## License

Copyright (c) 2025 Penterep Security s.r.o.

ptodnes is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptodnes is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptodnes. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!

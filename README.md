## Pass Cover
Nowadays, when every user has numerous passwords for different services, password management has become an important topic. It should be simple and understandable for everyone.

Pass Cover is an extension for Pass, the standard Unix password manager. It is believed that Pass Cover will improve the user experience and enhance metadata privacy. This work aims to contribute to a better digital world.

## Requirements

- Python 3.8+
- GPG (`gpg`) installed
- A GPG key configured
- `~/.password-store/.gpg-id` file

## Quick Start
### Installation (Ubuntu, Debian, Fedora)
```
git clone https://github.com/adgloriaml/pass-cover.git
cd pass-cover
chmod +x pass_cover.py
```

## Usage

Password store inizialization: 
```pass init <your-gpg-id>```

Add a password:
```./pass_cover.py insert <name>```

Show a password:
```./pass_cover.py show <name>```

List all entries:
```./pass_cover.py list```

Search for entries:
```./pass_cover.py search <query>```

Remove an entry:
```./pass_cover.py remove <name>```

Rename an entry: 
```./pass_cover.py rename <old-name> <new-name>```

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE.txt) file for details.

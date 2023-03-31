# master-password
[![AHK](https://img.shields.io/badge/ahk-2.0.2-C3D69B.svg?style=flat-square)]()
[![OS](https://img.shields.io/badge/os-windows-C3D69B.svg?style=flat-square)]()

Master Password is an application that never stores passwords.


## Features

- todo


## Screenshots

![MasterPassword](img/MasterPassword.png)


## Usage/Examples

To start it, simply call the function MasterPassword()
```autohotkey
MasterPassword()
```

To start the programme with extra protection (seed), specify a path to a file or place a file with the name seed.txt (default) in the same folder
```autohotkey
; checks whether a file with the name 'seed.txt' exists in the same folder.
MsterPassword()

; uses the file 'C:\private\secret.txt' as seed
MasterPassword("C:\private\secret.txt")
```


## Roadmap

- Revision of the GUI

- Add more options


## FAQ

#### How does it work?

```
master_key    = PBKDF2-SHA512 (user_name, master_password (+ seed) )
site_key      = HMAC-SHA512 ( site_name + site_counter, master_key )
site_password = PW-TAMPLATE ( site_key )
```


## Copyright and License
[![MIT License](https://img.shields.io/github/license/jNizM/master-password.svg?style=flat-square&color=C3D69B)](LICENSE)


## Donations
[![PayPal](https://img.shields.io/badge/paypal-donate-B2A2C7.svg?style=flat-square)](https://www.paypal.me/smithz)
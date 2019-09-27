# masterpass
MasterPass php kütüphanesi


## not: 
Sadece Token Generatör'ünü kullanın masterpass ekibi javascript SDK sını incelemeden kullanmanıza izin vermeyecektir. Kendi kütüphanelerinde PHP token generatör olmadığından dolayı hazırlamış bulunmaktayım

install
```php
composer require akalod/masterpass
```
example
```php
use akalod\MasterPass;

echo MasterPass:generateToken($userId,$gsm);
```
